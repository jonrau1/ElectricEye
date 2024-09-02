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
from datetime import datetime, timezone, UTC
from snowflake.connector import cursor
from check_register import CheckRegister
import base64
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SnowflakeAccountAuditor")

registry = CheckRegister()

def get_snowflake_security_integrations(cache: dict, snowflakeCursor: cursor.SnowflakeCursor) -> dict:
    """
    Get the Snowflake security integrations for the account from the SHOW INTEGRATIONS query.
    """
    response = cache.get("get_snowflake_security_integrations")
    if response:
        return response
    
    query = "SHOW INTEGRATIONS"
    
    cache["get_snowflake_security_integrations"] = snowflakeCursor.execute(query).fetchall()

    return cache["get_snowflake_security_integrations"]

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
def snowflake_account_sso_enabled_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.1] Snowflake Accounts have Single Sign-On (SSO) enabled"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    payload = get_snowflake_security_integrations(cache, snowflakeCursor)

    ssoCheck = [integ for integ in payload if "saml" in str(integ["type"]).lower() or "oauth" in str(integ["type"]).lower()]

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
                    "ISO 27001:2013 A.9.2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.3",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.5"
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
                    "ISO 27001:2013 A.9.2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.3",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.5"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("snowflake.account")
def snowflake_account_scim_enabled_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.2] Snowflake Accounts have SCIM enabled"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    payload = get_snowflake_security_integrations(cache, snowflakeCursor)

    scimCheck = [integ for integ in payload if str(integ["type"]).lower() == "scim"]

    # B64 encode all of the details for the Asset
    assetJson = json.dumps(scimCheck,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if scimCheck:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-scim-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.2] Snowflake Accounts have SCIM enabled",
            "Description": f"Snowflake account {snowflakeAccountId} has System for Cross-domain Identity Management (SCIM) enabled.",
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
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.DS-4",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 AU-4",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-7",
                    "NIST SP 800-53 Rev. 4 CP-8",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 CP-13",
                    "NIST SP 800-53 Rev. 4 PL-8",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "NIST SP 800-53 Rev. 4 SC-5",
                    "NIST SP 800-53 Rev. 4 SC-6",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.12.3.1",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.2",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.3",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.5",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.7"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    # this is a failing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-scim-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.2] Snowflake Accounts have SCIM enabled",
            "Description": f"Snowflake account {snowflakeAccountId} does not have System for Cross-domain Identity Management (SCIM) enabled. SCIM is an open specification designed to help facilitate the automated management of user identities and groups (i.e. roles) in cloud applications using RESTful APIs. Snowflake supports SCIM 2.0 integration with Okta, Microsoft Azure AD and custom identity providers. Users and groups from the identity provider can be provisioned into Snowflake, which functions as the service provider. While SSO enables seamless authentication with a federated identity to the Snowflake application, user accounts still need to be created, managed, and deprovisioned. Operations like adding and deleting users, changing permissions, and adding new types of accounts usually take up valuable admin time and when done manually may be error-prone. With SCIM, user identities can be created either directly in your identity provider, or imported from external systems like HR software or Active Directory. SCIM enables IT departments to automate the user provisioning and deprovisioning process while also having a single system to manage permissions and groups. Since data is transferred automatically, risk of error is reduced.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on setting up SCIM in Snowflake refer to the CREATE SECURITY INTEGRATION (SCIM) section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/sql-reference/sql/create-security-integration-scim#examples"
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
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.DS-4",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 AU-4",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-7",
                    "NIST SP 800-53 Rev. 4 CP-8",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 CP-13",
                    "NIST SP 800-53 Rev. 4 PL-8",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "NIST SP 800-53 Rev. 4 SC-5",
                    "NIST SP 800-53 Rev. 4 SC-6",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.12.3.1",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.2",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.3",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.5",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.7"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("snowflake.account")
def snowflake_admin_15min_session_timeout_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.3] Snowflake Accounts should ensure that admins roles have a 15 minute session timeout"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    query = """
    WITH PRIV_USERS AS ( SELECT DISTINCT GRANTEE_NAME FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS WHERE DELETED_ON IS NULL AND ROLE IN ('ACCOUNTADMIN','SECURITYADMIN') AND DELETED_ON IS NULL ), POLICY_REFS AS ( SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.SESSION_POLICIES AS B ON A.POLICY_ID = B.ID WHERE A.POLICY_KIND = 'SESSION_POLICY' AND A.POLICY_STATUS = 'ACTIVE' AND A.REF_ENTITY_DOMAIN = 'USER' AND B.DELETED IS NULL AND B.SESSION_IDLE_TIMEOUT_MINS <= 15 ) SELECT A.*, B.POLICY_ID, B.POLICY_KIND, B.POLICY_STATUS, B.SESSION_IDLE_TIMEOUT_MINS FROM PRIV_USERS AS A LEFT JOIN POLICY_REFS AS B ON A.GRANTEE_NAME = B.REF_ENTITY_NAME WHERE B.POLICY_ID IS NULL;
    """

    # execute the CIS query, works pretty well actually...this SHOULDN'T return anything for it to pass
    q = snowflakeCursor.execute(query).fetchall()

    # B64 encode all of the details for the Asset
    assetJson = json.dumps(q,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if not q:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-admin-session-timeout-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.3] Snowflake Accounts should ensure that admins roles have a 15 minute session timeout",
            "Description": f"Snowflake account {snowflakeAccountId} configures session timeouts to 15 minutes or less for all users with SECURITYADMIN and/or ACCOUNTADMIN roles.",
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
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5",
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.9",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-admin-session-timeout-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDUIM"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.3] Snowflake Accounts should ensure that admins roles have a 15 minute session timeout",
            "Description": f"Snowflake account {snowflakeAccountId} does not configure session timeouts to 15 minutes or less for all users with SECURITYADMIN and/or ACCOUNTADMIN roles. A session begins when a user connects to Snowflake and authenticates successfully using a Snowflake programmatic client, Snowsight, or the classic web interface. A session is maintained indefinitely with continued user activity. After a period of inactivity in the session, known as the idle session timeout, the user must authenticate to Snowflake again. Session policies can be used to modify the idle session timeout period. The idle session timeout has a maximum value of four hours. Tightening up the idle session timeout reduces sensitive data exposure risk when users forget to sign out of Snowflake and an unauthorized person gains access to their device. For more information on session policies in Snowflake refer to the Session Policies section of the Snowflake Documentation Portal.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for setting up session policies in Snowflake refer to the Snowflake Sessions & Session Policies section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/session-policies"
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
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5",
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.9",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("snowflake.account")
def snowflake_built_in_admin_roles_not_in_custom_role_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.4] Snowflake custom roles should not use built-in admin roles"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    query = """
    SELECT GRANTEE_NAME AS CUSTOM_ROLE, PRIVILEGE AS GRANTED_PRIVILEGE, NAME AS GRANTED_ROLE FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE GRANTED_ON = 'ROLE' AND NAME IN ('ACCOUNTADMIN','SECURITYADMIN') AND DELETED_ON IS NULL
    """

    q = snowflakeCursor.execute(query).fetchall()
    # execute the CIS query, works pretty well for this too, the query should only return a single row: [{'CUSTOM_ROLE': 'ACCOUNTADMIN', 'GRANTED_PRIVILEGE': 'USAGE', 'GRANTED_ROLE': 'SECURITYADMIN'}]. If there is more than one entry in the returned list, or the entry does not match this, it's a fail
    builtInAdminNotUsedInCustomRole = False
    if len(q) == 1:
        if q[0]["CUSTOM_ROLE"] == "ACCOUNTADMIN" and q[0]["GRANTED_PRIVILEGE"] == "USAGE" and q[0]["GRANTED_ROLE"] == "SECURITYADMIN":
            builtInAdminNotUsedInCustomRole = True

    # B64 encode all of the details for the Asset
    assetJson = json.dumps(q,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if builtInAdminNotUsedInCustomRole is True:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-admin-session-timeout-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.4] Snowflake custom roles should not use built-in admin roles",
            "Description": f"Snowflake account {snowflakeAccountId} does not use SECURITYADMIN and/or ACCOUNTADMIN roles within custom roles.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for setting up custom roles and general access control in Snowflake refer to the Overview of Access Control section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/security-access-control-overview"
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
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "AICPA TSC CC6.3",
                    "ISO 27001:2013 A.6.1.2",
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.2.3",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.13",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.2"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    # this is a failing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-admin-session-timeout-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.4] Snowflake custom roles should not use built-in admin roles",
            "Description": f"Snowflake account {snowflakeAccountId} uses SECURITYADMIN and/or ACCOUNTADMIN roles within custom roles. The principle of least privilege requires that every identity is only given privileges that are necessary to complete its tasks. The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is intended for performing initial setup and managing account-level objects. SECURITYADMIN role can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles should be used for performing daily non-administrative tasks in a Snowflake account. Granting ACCOUNTADMIN role to any custom role effectively elevates privileges of that role to the ACCOUNTADMIN role privileges. Roles that include the ACCOUNTADMIN role can then be mistakenly used in access grants that do not require ACCOUNTADMIN privileges thus violating the principle of least privilege and increasing the attack surface. The same logic applies to the SECURITYADMIN role. For more information refer to the remediation section.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for setting up custom roles and general access control in Snowflake refer to the Overview of Access Control section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/security-access-control-overview"
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
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "AICPA TSC CC6.3",
                    "ISO 27001:2013 A.6.1.2",
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.2.3",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.13",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.2"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("snowflake.account")
def snowflake_tasks_not_owned_by_admins_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.5] Snowflake tasks should not be owned by ACCOUNTADMIN or SECURITYADMIN roles"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    query = """
    SELECT NAME AS STORED_PROCEDURE_NAME, GRANTED_TO, GRANTEE_NAME AS ROLE_NAME, PRIVILEGE FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE GRANTED_ON = 'TASK' AND DELETED_ON IS NULL AND GRANTED_TO = 'ROLE' AND PRIVILEGE = 'OWNERSHIP' AND GRANTEE_NAME IN ('ACCOUNTADMIN' , 'SECURITYADMIN')
    """
    # as long as this returns an empty list, it's a pass
    q = snowflakeCursor.execute(query).fetchall()
    
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(q,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if not q:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-tasks-owned-by-default-admin-roles-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.5] Snowflake tasks should not be owned by ACCOUNTADMIN or SECURITYADMIN roles",
            "Description": f"Snowflake account {snowflakeAccountId} does not have any tasks owned by SECURITYADMIN and/or ACCOUNTADMIN roles. This check does not take into account tasks owned by custom roles using the ACCOUNTADMIN or SECURITYADMIN roles.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on managing Snowflake Task ownership and general security best practices in Snowflake refer to the Manage task graph ownership section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/tasks-graphs#label-task-dag-ownership"
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
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
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
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.14",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.2"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    # this is a failing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-tasks-owned-by-default-admin-roles-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.5] Snowflake tasks should not be owned by ACCOUNTADMIN or SECURITYADMIN roles",
            "Description": f"Snowflake account {snowflakeAccountId} has at least one task owned by SECURITYADMIN and/or ACCOUNTADMIN roles. The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is intended for performing initial setup and managing account-level objects. SECURITYADMIN role can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles should be used for running Snowflake tasks. A task should be running using a custom role containing only those privileges that are necessary for successful execution of the task. Snowflake executes tasks with the privileges of the task owner. The role that has OWNERSHIP privilege on the task owns the task. To avoid granting a task inappropriate privileges, the OWNERSHIP privilege on the task run as owner should be assigned to a custom role containing only those privileges that are necessary for successful execution of the task. This check does not take into account tasks owned by custom roles using the ACCOUNTADMIN or SECURITYADMIN roles. For more information refer to the remediation section.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on managing Snowflake Task ownership and general security best practices in Snowflake refer to the Manage task graph ownership section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/tasks-graphs#label-task-dag-ownership"
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
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
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
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.14",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.2"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("snowflake.account")
def snowflake_tasks_not_running_with_admin_privs_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.6] Snowflake tasks should not run with ACCOUNTADMIN or SECURITYADMIN role privileges"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    query = """
    SELECT NAME AS STORED_PROCEDURE_NAME, GRANTED_TO, GRANTEE_NAME AS ROLE_NAME, PRIVILEGE FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE GRANTED_ON = 'TASK' AND DELETED_ON IS NULL AND GRANTED_TO = 'ROLE' AND GRANTEE_NAME IN ('ACCOUNTADMIN' , 'SECURITYADMIN')
    """
    # as usual, as long as this returns an empty list, it's a pass
    q = snowflakeCursor.execute(query).fetchall()
    
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(q,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if not q:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-tasks-run-with-admin-privileges-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.6] Snowflake tasks should not run with ACCOUNTADMIN or SECURITYADMIN role privileges",
            "Description": f"Snowflake account {snowflakeAccountId} does not have any tasks that run with ACCOUNTADMIN or SECURITYADMIN role privileges. This check does not take into account tasks running with custom roles using the ACCOUNTADMIN or SECURITYADMIN roles.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on managing Snowflake Task ownership and general security best practices in Snowflake refer to the Manage task graph ownership section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/tasks-graphs#label-task-dag-ownership"
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
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
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
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.15",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.2"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    # this is a failing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-tasks-run-with-admin-privileges-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.6] Snowflake tasks should not run with ACCOUNTADMIN or SECURITYADMIN role privileges",
            "Description": f"Snowflake account {snowflakeAccountId} has at least one task that runs with ACCOUNTADMIN or SECURITYADMIN role privileges. The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is intended for performing initial setup and managing account-level objects. SECURITYADMIN role can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles should be used for running Snowflake tasks. A task should be running using a custom role containing only those privileges that are necessary for successful execution of the task. If a threat actor finds a way to influence or hijack the task execution flow, they may be able to exploit privileges given to the task. In the case of an ACCOUNTADMIN or SECURITYADMIN roles, that may lead to a full account takeover. Additionally, a mistake in the task implementation coupled with excessive privileges may lead to a reliability incident, e.g. accidentally dropping database objects. This check does not take into account tasks running with custom roles using the ACCOUNTADMIN or SECURITYADMIN roles.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on managing Snowflake Task ownership and general security best practices in Snowflake refer to the Manage task graph ownership section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/tasks-graphs#label-task-dag-ownership"
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
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
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
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.15",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.2"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("snowflake.account")
def snowflake_stored_procs_not_owned_by_admins_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.7] Snowflake stored procedures should not run with ACCOUNTADMIN or SECURITYADMIN role privileges"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    query = """
    SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.PROCEDURES WHERE DELETED IS NULL AND PROCEDURE_OWNER IN ('ACCOUNTADMIN','SECURITYADMIN')
    """
    # as usual, as long as this returns an empty list, it's a pass
    q = snowflakeCursor.execute(query).fetchall()
    
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(q,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if not q:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-stored-procs-owned-by-default-admin-roles-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.7] Snowflake stored procedures should not run with ACCOUNTADMIN or SECURITYADMIN role privileges",
            "Description": f"Snowflake account {snowflakeAccountId} does not have any stored procedures that are owned by ACCOUNTADMIN or SECURITYADMIN roles. This check does not take into account tasks running with custom roles using the ACCOUNTADMIN or SECURITYADMIN roles.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on managing Snowflake Stored Procedure ownership and general security best practices in Snowflake refer to the Understanding caller's rights and owner's rights stored procedures section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-rights"
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
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
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
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.16",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.2"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    # this is a failing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-stored-procs-owned-by-default-admin-roles-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.7] Snowflake stored procedures should not run with ACCOUNTADMIN or SECURITYADMIN role privileges",
            "Description": f"Snowflake account {snowflakeAccountId} does not have any stored procedures that are owned by ACCOUNTADMIN or SECURITYADMIN roles. Snowflake executes stored procedures with the privileges of the stored procedure owner or the caller. Role that has OWNERSHIP privilege on the stored procedure owns it. To avoid granting a stored procedure inappropriate privileges, the OWNERSHIP privilege on the stored procedure run as owner should be assigned to a custom role containing only those privileges that are necessary for successful execution of the stored procedure. If a threat actor finds a way to influence or hijack the stored procedure execution flow, they may be able to exploit privileges given to the stored procedure. In the case of an ACCOUNTADMIN or SECURITYADMIN roles, that may lead to a full account takeover. Additionally, a mistake in the stored procedure implementation coupled with excessive privileges may lead to a reliability incident, e.g. accidentally dropping database objects. This check does not take into account tasks running with custom roles using the ACCOUNTADMIN or SECURITYADMIN roles. For more information refer to the remediation section.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on managing Snowflake Stored Procedure ownership and general security best practices in Snowflake refer to the Understanding caller's rights and owner's rights stored procedures section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-rights"
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
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
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
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.16",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.2"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("snowflake.account")
def snowflake_stored_procs_not_running_with_admin_privs_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.8] Snowflake stored procedures should not run with ACCOUNTADMIN or SECURITYADMIN role privileges"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    query = """
    SELECT NAME AS STORED_PROCEDURE_NAME, GRANTED_TO, GRANTEE_NAME AS ROLE_NAME FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE GRANTED_ON = 'PROCEDURE' AND DELETED_ON IS NULL AND GRANTED_TO = 'ROLE' AND GRANTEE_NAME IN ('ACCOUNTADMIN' , 'SECURITYADMIN');
    """
    # as usual, as long as this returns an empty list, it's a pass
    q = snowflakeCursor.execute(query).fetchall()
    
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(q,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if not q:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-stored-procs-run-with-admin-privileges-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.8] Snowflake stored procedures should not run with ACCOUNTADMIN or SECURITYADMIN role privileges",
            "Description": f"Snowflake account {snowflakeAccountId} does not have any stored procedures that run with ACCOUNTADMIN or SECURITYADMIN role privileges. This check does not take into account stored procedures running with custom roles using the ACCOUNTADMIN or SECURITYADMIN roles.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on managing Snowflake Stored Procedure ownership and general security best practices in Snowflake refer to the Understanding caller's rights and owner's rights stored procedures section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-rights"
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
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
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
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.17",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.2"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    # this is a failing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-stored-procs-run-with-admin-privileges-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.8] Snowflake stored procedures should not run with ACCOUNTADMIN or SECURITYADMIN role privileges",
            "Description": f"Snowflake account {snowflakeAccountId} has at least one stored procedure that runs with ACCOUNTADMIN or SECURITYADMIN role privileges. Snowflake stored procedures should not run with the ACCOUNTADMIN or SECURITYADMIN roles. Instead, stored procedures should be run using a custom role containing only those privileges that are necessary for successful execution of the stored procedure. If a threat actor finds a way to influence or hijack the stored procedure execution flow, they may be able to exploit privileges given to the stored procedure. In the case of an ACCOUNTADMIN or SECURITYADMIN roles, that may lead to a full account takeover. Additionally, a mistake in the stored procedure implementation coupled with excessive privileges may lead to a reliability incident, e.g. accidentally dropping database objects. This check does not take into account stored procedures running with custom roles using the ACCOUNTADMIN or SECURITYADMIN roles. For more information refer to the remediation section.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on managing Snowflake Stored Procedure ownership and general security best practices in Snowflake refer to the Understanding caller's rights and owner's rights stored procedures section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-rights"
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
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
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
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.17",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.1",
                    "CIS Snowflake Foundations Benchmark V1.0.0 2.2"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("snowflake.account")
def snowflake_account_password_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.9] Snowflake Accounts should configure a password policy"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    payload = get_snowflake_password_policy(cache, snowflakeCursor)

    # B64 encode all of the details for the Asset
    assetJson = json.dumps(payload,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if payload:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-password-policy-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.9] Snowflake Accounts should configure a password policy",
            "Description": f"Snowflake account {snowflakeAccountId} has at least one password policy configured.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for user management and password policies in Snowflake refer to the User management section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/admin-user-management"
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
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
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
    # this is a failing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-password-policy-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.9] Snowflake Accounts should configure a password policy",
            "Description": f"Snowflake account {snowflakeAccountId} does not have a password policy configured. A password policy specifies the requirements that must be met to create and reset a password to authenticate to Snowflake. Beyond a strong password policy, Snowflake also supports multi-factor authentication (MFA) for additional security. A password policy should be configured to enforce strong password requirements, such as minimum length, complexity, and expiration. For more information on password policies in Snowflake refer to the User management section of the Snowflake Documentation Portal.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for user management and password policies in Snowflake refer to the User management section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/admin-user-management"
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
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
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

@registry.register_check("snowflake.account")
def snowflake_account_password_length_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.10] Snowflake password policies should enforce a minimum password length of at least 14 characters"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    for policy in get_snowflake_password_policy(cache, snowflakeCursor):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(policy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        pwPolicyName = policy.get("NAME")

        # Evaluate min length only from "PASSWORD_MIN_LENGTH" key to set policy passing
        pwPolicyPasses = False
        if policy.get("PASSWORD_MIN_LENGTH") >= 14:
            pwPolicyPasses = True

        # this is a passing check
        if pwPolicyPasses is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{pwPolicyName}/snowflake-account-password-length-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": snowflakeAccountId,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Snowflake.Account.10] Snowflake password policies should enforce a minimum password length of at least 14 characters",
                "Description": f"Snowflake password policy {pwPolicyName} requires at least 14 characters for the minimum password length.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on best practices for user management and password policies in Snowflake refer to the User management section of the Snowflake Documentation Portal.",
                        "Url": "https://docs.snowflake.com/en/user-guide/admin-user-management"
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
                    "AssetService": "Snowflake Password Policy",
                    "AssetComponent": "Policy"
                },
                "Resources": [
                    {
                        "Type": "SnowflakePasswordPolicy",
                        "Id": pwPolicyName,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
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
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        # this is a failing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{pwPolicyName}/snowflake-account-password-length-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": snowflakeAccountId,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Snowflake.Account.10] Snowflake password policies should enforce a minimum password length of at least 14 characters",
                "Description": f"Snowflake password policy {pwPolicyName} does not require at least 14 characters for the minimum password length. Snowflake supports setting a password policy for your Snowflake account and for individual users. Only one password policy can be set at any given time for your Snowflake account or a user. If a password policy exists for the Snowflake account and another password policy is set for a user in the same Snowflake account, the user-level password policy takes precedence over the account-level password policy. While Snowflake recommends configuring SSO authentication for users and ensuring that SSO users do not have a password set, there may be exceptions when users still need to log in with a password (e.g., setting up a break-glass user with password login to recover from SSO outages). For those few users that still need to have a password, setting a password policy can help ensure that, throughout subsequent password changes, the passwords used remain complex and therefore harder to guess or brute-force. For more information refer to the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on best practices for user management and password policies in Snowflake refer to the User management section of the Snowflake Documentation Portal.",
                        "Url": "https://docs.snowflake.com/en/user-guide/admin-user-management"
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
                    "AssetService": "Snowflake Password Policy",
                    "AssetComponent": "Policy"
                },
                "Resources": [
                    {
                        "Type": "SnowflakePasswordPolicy",
                        "Id": pwPolicyName,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
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
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.5"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("snowflake.account")
def snowflake_monitor_session_keep_alive_commands_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.11] Snowflake Accounts should be monitored for users extending their sessions"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    query = """
    SELECT DISTINCT session_id FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
    WHERE query_type = 'ALTER_SESSION'
    AND query_text ilike '%CLIENT_SESSION_KEEP_ALIVE%TRUE%'
    AND query_text not ilike '%CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY%'
    """

    # execute the CIS query, works pretty well actually...this SHOULDN'T return anything for it to pass
    q = snowflakeCursor.execute(query).fetchall()

    # B64 encode all of the details for the Asset
    assetJson = json.dumps(q,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if not q:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-session-timeout-keep-alive-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.11] Snowflake Accounts should be monitored for users extending their sessions",
            "Description": f"Snowflake account {snowflakeAccountId} does not have any users extending their sessions.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices on sessions in Snowflake refer to the Snowflake Sessions & Session Policies section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/session-policies#considerations"
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
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.DS-4",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 AU-4",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-7",
                    "NIST SP 800-53 Rev. 4 CP-8",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 CP-13",
                    "NIST SP 800-53 Rev. 4 PL-8",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "NIST SP 800-53 Rev. 4 SC-5",
                    "NIST SP 800-53 Rev. 4 SC-6",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.12.3.1",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    # this is a failing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-session-timeout-keep-alive-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.11] Snowflake Accounts should be monitored for users extending their sessions",
            "Description": f"Snowflake account {snowflakeAccountId} has at least one user extending their session. If a client supports the CLIENT_SESSION_KEEP_ALIVE option and the option is set to TRUE, the client preserves the Snowflake session indefinitely as long as the connection to Snowflake is active. Otherwise, if the option is set to FALSE, the session ends after 4 hours. When possible, avoid using this option since it can result in many open sessions and place a greater demand on resources which can lead to a performance degradation. In rarer cases, this can become a security risk if a session is hijacked due to a further downstream vulnerability. For more information refer to the remediation section.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices on sessions in Snowflake refer to the Snowflake Sessions & Session Policies section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/session-policies#considerations"
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
                "Status": "RESOLVED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.DS-4",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 AU-4",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-7",
                    "NIST SP 800-53 Rev. 4 CP-8",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 CP-13",
                    "NIST SP 800-53 Rev. 4 PL-8",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "NIST SP 800-53 Rev. 4 SC-5",
                    "NIST SP 800-53 Rev. 4 SC-6",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.12.3.1",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("snowflake.account")
def snowflake_network_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor, serviceAccountExemptions: list[str]
) -> dict:
    """[Snowflake.Account.12] Snowflake Accounts should have a network policy enabled"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    query = "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.NETWORK_POLICIES"

    # if this is empty it is a failing check
    q = snowflakeCursor.execute(query).fetchall()

    # B64 encode all of the details for the Asset
    assetJson = json.dumps(q,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if not q:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-network-policy-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.12] Snowflake Accounts should have a network policy enabled",
            "Description": f"Snowflake account {snowflakeAccountId} has at least one network policy. This check does not evaluate the actual contents of the network policy, only that one exists.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for network security and creating Network Policies in Snowflake refer to the Controlling network traffic with network policies section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/network-policies"
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
                    "CIS Snowflake Foundations Benchmark V1.0.0 3.1"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    # this is a failing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-network-policy-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.12] Snowflake Accounts should have a network policy enabled",
            "Description": f"Snowflake account {snowflakeAccountId} does not have a network policy. This check does not evaluate the actual contents of the network policy, only that one exists. Snowflake network policies are used to control network traffic to and from your Snowflake account. Network policies are defined using a set of rules that specify the conditions under which network traffic is allowed or denied. For more information refer to the remediation section.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for network security and creating Network Policies in Snowflake refer to the Controlling network traffic with network policies section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/network-policies"
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
                    "CIS Snowflake Foundations Benchmark V1.0.0 3.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

# EOF