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
logger = logging.getLogger("SnowflakeUserAuditor")

registry = CheckRegister()

def timestamp_to_iso(timestampNtz: str | None) -> str | None:
    """
    Receives from Snowflake and transforms to ISO 8601 format stringified datetime objects. If the timestamp is None, it returns None.
    """
    if timestampNtz is None:
        return None

    try:
        dt = datetime.strptime(str(timestampNtz), '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        dt = datetime.strptime(str(timestampNtz), '%Y-%m-%d %H:%M:%S')
    
    dt = dt.replace(tzinfo=timezone.utc).isoformat()

    return str(dt)

def get_roles_for_user(username: str, snowflakeCursor: cursor.SnowflakeCursor) -> tuple[list[str | None], bool]:
    """
    Retrieves the assigned grants (Roles) for a given user
    """

    query = f"""
    SHOW GRANTS TO USER "{username}"
    """

    adminRoles = ["ACCOUNTADMIN","ORGADMIN","SECURITYADMIN","SYSADMIN"]
    roles = []

    try:
        q = snowflakeCursor.execute(query)
        for row in q.fetchall():
            roles.append(row["role"])
    except TypeError:
        logger.warn(f"no roles for the user: {username}")
    except snowerrors.ProgrammingError as spe:
        if "does not exist" in str(spe):
            logger.warning("Snowflake User %s is inactive or roles are unable to be retrieved.", username)
    except Exception as e:
        logger.warning("Exception encounterd while trying to get roles for user %s: %s", username, e)
        return (list(), None)
    
    if roles:
        if any(adminrole in roles for adminrole in adminRoles):
            isAdmin = True
        else:
            isAdmin = False
    else:
        isAdmin = False

    return roles, isAdmin

def check_user_logon_without_mfa(username: str, snowflakeCursor: cursor.SnowflakeCursor) -> tuple[bool, int]:
    """Pulls distinct logs for a user where they did not use MFA, returns True if they did not use MFA along with the amount of times"""

    # Check for specific users that used Password, didn't fail, and didn't use a 2FA factor
    query = f"""
    SELECT DISTINCT
        USER_NAME,
        IS_SUCCESS
        FIRST_AUTHENTICATION_FACTOR,
        SECOND_AUTHENTICATION_FACTOR
    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE USER_NAME = '{username}'
    AND IS_SUCCESS = 'YES'
    AND FIRST_AUTHENTICATION_FACTOR = 'PASSWORD'
    AND SECOND_AUTHENTICATION_FACTOR IS NULL
    """

    try:
        q = snowflakeCursor.execute(query).fetchall()
    except Exception as e:
        logger.warning("Exception encountered while trying to get logon history for Snowflake user %s: %s", username, e)
        return (False, 0)

    if q:
        loginWithoutMfa = True
        logonsWithoutMfaCount = len(q)
    else:
        loginWithoutMfa = False
        logonsWithoutMfaCount = 0

    return (loginWithoutMfa, logonsWithoutMfaCount)

def get_snowflake_users(cache: dict, snowflakeCursor: cursor.SnowflakeCursor) -> dict:
    """
    Gathers a list of users from the SNOWFLAKE.ACCOUNT_USAGE.USERS table, enriches the data with Snowflake Roles and Snowflake Logon data, and returns a list of dictionaries containing user data. This is written into the ElectricEye cache.
    """
    response = cache.get("get_snowflake_users")
    if response:
        return response
    
    snowflakeUsers = []

    # Use the almighty SQL query to get all the users
    query = f"""
    SELECT DISTINCT
        user_id,
        name,
        to_timestamp_ntz(created_on) as created_on,
        to_timestamp_ntz(deleted_on) as deleted_on,
        login_name,
        display_name,
        first_name,
        last_name,
        email,
        must_change_password,
        has_password,
        comment,
        disabled,
        snowflake_lock,
        default_warehouse,
        default_namespace,
        default_role,
        ext_authn_duo,
        ext_authn_uid,
        bypass_mfa_until,
        to_timestamp_ntz(last_success_login) as last_success_login,
        to_timestamp_ntz(expires_at) as expires_at,
        to_timestamp_ntz(locked_until_time) as locked_until_time,
        has_rsa_public_key,
        to_timestamp_ntz(password_last_set_time) as password_last_set_time,
        owner,
        default_secondary_role
    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
    """

    try:
        q = snowflakeCursor.execute(query)
        for column in q.fetchall():
            username = column["NAME"]
            try:
                pwLastSetTime = str(column["PASSWORD_LAST_SET_TIME"])
            except KeyError:
                pwLastSetTime = None

            roleData = get_roles_for_user(username, snowflakeCursor)

            logins = check_user_logon_without_mfa(username, snowflakeCursor)

            snowflakeUsers.append(
                {
                    "user_id": column["USER_ID"],
                    "name": username,
                    "created_on": timestamp_to_iso(column["CREATED_ON"]),
                    "deleted_on": timestamp_to_iso(column["DELETED_ON"]),
                    "login_name": column["LOGIN_NAME"],
                    "display_name": column["DISPLAY_NAME"],
                    "first_name": column["FIRST_NAME"],
                    "last_name": column["LAST_NAME"],
                    "email": column["EMAIL"],
                    "assigned_roles": roleData[0],
                    "is_admin": roleData[1],
                    "logged_on_without_mfa": logins[0],
                    "total_logons_without_mfa": logins[1],
                    "must_change_password": column["MUST_CHANGE_PASSWORD"],
                    "has_password": column["HAS_PASSWORD"],
                    "comment": column["COMMENT"],
                    "disabled": column["DISABLED"],
                    "snowflake_lock": column["SNOWFLAKE_LOCK"],
                    "default_warehouse": column["DEFAULT_WAREHOUSE"],
                    "default_namespace": column["DEFAULT_NAMESPACE"],
                    "default_role": column["DEFAULT_ROLE"],
                    "ext_authn_duo": column["EXT_AUTHN_DUO"],
                    "ext_authn_uid": column["EXT_AUTHN_UID"],
                    "bypass_mfa_until": timestamp_to_iso(column["BYPASS_MFA_UNTIL"]),
                    "last_success_login": timestamp_to_iso(column["LAST_SUCCESS_LOGIN"]),
                    "expires_at": timestamp_to_iso(column["EXPIRES_AT"]),
                    "locked_until_time": timestamp_to_iso(column["LOCKED_UNTIL_TIME"]),
                    "has_rsa_public_key": column["HAS_RSA_PUBLIC_KEY"],
                    "password_last_set_time": timestamp_to_iso(pwLastSetTime),
                    "owner": column["OWNER"],
                    "default_secondary_role": column["DEFAULT_SECONDARY_ROLE"]
                }
            )
    except Exception as e:
        logger.warning("Exception encountered while trying to get Snowflake users: %s", e)
    
    cache["get_snowflake_users"] = snowflakeUsers

    return cache["get_snowflake_users"]

@registry.register_check("snowflake.users")
def snowflake_password_assigned_user_has_mfa_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor
) -> dict:
    """[Snowflake.Users.1] Snowflake users with passwords should have MFA enabled"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    # Get all of the users
    for user in get_snowflake_users(cache, snowflakeCursor):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        username = user["name"]
        # this is a passing check
        if user["ext_authn_duo"] is True and user["has_password"] is True and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/password-user-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.1] Snowflake users with passwords should have MFA enabled",
                "Description": f"Snowflake user {username} has a password assigned and has MFA enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on MFA best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                        "Url": "https://community.snowflake.com/s/article/Snowflake-Security-Overview-and-Best-Practices?mkt_tok=MjUyLVJGTy0yMjcAAAGTVPcnsobib0St0CwRwVZ4sfwHPicq12DnL_MX_bz-yG4OgkADmIh6ll3PcRhIqFeezBwdFSNL-ipp9vJHUV6hRiKUK2b-0f5_HGpkwz7pTG2_w6cO9Q"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        # this is a failing check
        if user["ext_authn_duo"] is False and user["has_password"] is True and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/password-user-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.1] Snowflake users with passwords should have MFA enabled",
                "Description": f"Snowflake user {username} has a password assigned but does not have MFA enabled. Multi-factor authentication (MFA) is a security control used to add an additional layer of login security. It works by requiring the user to present two or more proofs (factors) of user identity. An MFA example would be requiring a password and a verification code delivered to the user's phone during user sign-in. The MFA feature for Snowflake users is powered by the Duo Security service. This check does not account for SCIM or IdP-managed users with external MFA devices assigned, that criteria should be manually verified. Refer to the remediation section if this behavior is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on MFA best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                        "Url": "https://community.snowflake.com/s/article/Snowflake-Security-Overview-and-Best-Practices?mkt_tok=MjUyLVJGTy0yMjcAAAGTVPcnsobib0St0CwRwVZ4sfwHPicq12DnL_MX_bz-yG4OgkADmIh6ll3PcRhIqFeezBwdFSNL-ipp9vJHUV6hRiKUK2b-0f5_HGpkwz7pTG2_w6cO9Q"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("snowflake.users")
def snowflake_service_account_user_uses_keypair_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor
) -> dict:
    """[Snowflake.Users.2] Snowflake 'service account' users should use RSA key pairs for authentication"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    # Get all of the users
    for user in get_snowflake_users(cache, snowflakeCursor):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        username = user["name"]
        # this is a passing check
        if user["has_rsa_public_key"] is True and user["has_password"] is False and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/service-account-user-rsa-keypair-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.2] Snowflake 'service account' users should use RSA key pairs for authentication",
                "Description": f"Snowflake 'service account' user {username} uses an RSA key pair for authentication. On the platform level Snowflake does not differentiate between Snowflake users created for and used by humans and Snowflake users created for and used by services. This check assumes that users without a password enabled are service accounts.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on RSA keypair best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                        "Url": "https://community.snowflake.com/s/article/Snowflake-Security-Overview-and-Best-Practices?mkt_tok=MjUyLVJGTy0yMjcAAAGTVPcnsobib0St0CwRwVZ4sfwHPicq12DnL_MX_bz-yG4OgkADmIh6ll3PcRhIqFeezBwdFSNL-ipp9vJHUV6hRiKUK2b-0f5_HGpkwz7pTG2_w6cO9Q"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        # this is a failing check
        if user["has_rsa_public_key"] is False and user["has_password"] is False and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/service-account-user-rsa-keypair-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.2] Snowflake 'service account' users should use RSA key pairs for authentication",
                "Description": f"Snowflake 'service account' user {username} does not use an RSA key pair for authentication. On the platform level Snowflake does not differentiate between Snowflake users created for and used by humans and Snowflake users created for and used by services. This check assumes that users without a password enabled are service accounts. Password-based authentication used by humans can be augmented by a second factor (MFA), e.g. a hardware token, or a security code pushed to a mobile device. Services and automation cannot be easily configured to authenticate with a second factor. Instead, for such use cases, Snowflake supports using key pair authentication as a more secure alternative to password-based authentication. Note that password-based authentication for a service account can be enabled along with a key-based authentication. To ensure that only key-based authentication is enabled for a service account, the PASSWORD parameter for that Snowflake user must be set to null. For more information on key pair authentication, refer to the Snowflake documentation.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on RSA keypair best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                        "Url": "https://community.snowflake.com/s/article/Snowflake-Security-Overview-and-Best-Practices?mkt_tok=MjUyLVJGTy0yMjcAAAGTVPcnsobib0St0CwRwVZ4sfwHPicq12DnL_MX_bz-yG4OgkADmIh6ll3PcRhIqFeezBwdFSNL-ipp9vJHUV6hRiKUK2b-0f5_HGpkwz7pTG2_w6cO9Q"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("snowflake.users")
def snowflake_disable_users_without_last_90_day_login_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor
) -> dict:
    """[Snowflake.Users.3] Snowflake users that have not logged in within the last 90 days should be disabled"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    # Get all of the users
    for user in get_snowflake_users(cache, snowflakeCursor):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        username = user["name"]

        # determine if there was a successful login in the last 90 days for users that are not disabled and have otherwise logged in
        passingCheck = True
        if user["last_success_login"] and user["disabled"] is "false" and user["deleted_on"] is None:
            lastLogin = datetime.fromisoformat(user["last_success_login"])
            ninetyDaysAgo = datetime.now(UTC) - timedelta(days=90)
            if lastLogin > ninetyDaysAgo:
                passingCheck = False

        # this is a passing check
        if passingCheck:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/disable-user-without-login-in-last-90-days-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "Snowflake users that have not logged in within the last 90 days should be disabled",
                "Description": f"Snowflake user {username} is either disabled, deleted, or has logged in within the last 90 days.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on user management best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                        "Url": "https://community.snowflake.com/s/article/Snowflake-Security-Overview-and-Best-Practices?mkt_tok=MjUyLVJGTy0yMjcAAAGTVPcnsobib0St0CwRwVZ4sfwHPicq12DnL_MX_bz-yG4OgkADmIh6ll3PcRhIqFeezBwdFSNL-ipp9vJHUV6hRiKUK2b-0f5_HGpkwz7pTG2_w6cO9Q"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.8",
                        "CIS Snowflake Foundations Benchmark V1.0.0 2.3"
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
                "Id": f"{snowflakeAccountId}/{username}/disable-user-without-login-in-last-90-days-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "Snowflake users that have not logged in within the last 90 days should be disabled",
                "Description": f"Snowflake user {username} has not logged in within the last 90 days and should be considered for disablement. Access grants tend to accumulate over time unless explicitly set to expire. Regularly revoking unused access grants and disabling inactive user accounts is a good countermeasure to this dynamic. If credentials of an inactive user account are leaked or stolen, it may take longer to discover the compromise. In Snowflake an user account can be disabled by users with the ACCOUNTADMIN role. Disabling inactive user accounts supports the principle of least privilege and generally reduces attack surface. For more information on user management best practices refer to the Snowflake documentation.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on user management best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                        "Url": "https://community.snowflake.com/s/article/Snowflake-Security-Overview-and-Best-Practices?mkt_tok=MjUyLVJGTy0yMjcAAAGTVPcnsobib0St0CwRwVZ4sfwHPicq12DnL_MX_bz-yG4OgkADmIh6ll3PcRhIqFeezBwdFSNL-ipp9vJHUV6hRiKUK2b-0f5_HGpkwz7pTG2_w6cO9Q"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.8",
                        "CIS Snowflake Foundations Benchmark V1.0.0 2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("snowflake.users")
def snowflake_accountadmins_have_email_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor
) -> dict:
    """[Snowflake.Users.4] Snowflake users assigned the ACCOUNTADMIN role should have an email address assigned"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    # Get all of the users
    for user in get_snowflake_users(cache, snowflakeCursor):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        username = user["name"]
        # pre-check email, the shit can be properly null or stupid sauce fr fr
        hasEmail = True
        if user["email"] is None or user["email"] == "":
            hasEmail = False
        # this is a passing check
        if "ACCOUNTADMIN" in user["assigned_roles"] and hasEmail is True and user["has_password"] is True and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/accountadmin-role-users-have-email-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.4] Snowflake users assigned the ACCOUNTADMIN role should have an email address assigned",
                "Description": f"Snowflake user {username} has the ACCOUNTADMIN role assigned and has an email addressed assigned as well. This only checks for the presence of an email for users that also have a password, since 'service accounts' do not have passwords and do not need an email address.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on assinging emails the the rationale for ACCOUNTADMINS to have emails refer to the Access control considerations section of the Snowflake Documentation Portal.",
                        "Url": "https://docs.snowflake.com/en/user-guide/security-access-control-considerations"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.11"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        # this is a failing check
        if "ACCOUNTADMIN" in user["assigned_roles"] and hasEmail is False and user["has_password"] is True and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/accountadmin-role-users-have-email-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.4] Snowflake users assigned the ACCOUNTADMIN role should have an email address assigned",
                "Description": f"Snowflake user {username} has the ACCOUNTADMIN role assigned and does not have an email addressed assigned. Every Snowflake user can be assigned an email address. The email addresses are then used by Snowflake features like notification integration, resource monitor and support cases to deliver email notifications to Snowflake users. In trial Snowflake accounts these email addresses are used for password reset functionality. The email addresses assigned to ACCOUNTADMIN users are used by Snowflake to notify administrators about important events related to their accounts. For example, ACCOUNTADMIN users are notified about impending expiration of SAML2 certificates or SCIM access tokens. If users with the ACCOUNTADMIN role are not assigned working email addresses that are being monitored and if SAML2 certificate used in SSO integration is not proactively renewed, expiration of SAML2 certificate may break the SSO authentication flow. Similarly, uncaught expiration of SCIM access token may break the SCIM integration. This only checks for the presence of an email for users that also have a password, since 'service accounts' do not have passwords and do not need an email address. For more information on user management best practices refer to the Snowflake documentation.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on assinging emails the the rationale for ACCOUNTADMINS to have emails refer to the Access control considerations section of the Snowflake Documentation Portal.",
                        "Url": "https://docs.snowflake.com/en/user-guide/security-access-control-considerations"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.11"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("snowflake.users")
def snowflake_admin_default_role_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor
) -> dict:
    """[Snowflake.Users.5] Snowflake users should not be assigned the ACCOUNTADMIN or SECURITYADMIN role as the default role"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    # Get all of the users
    for user in get_snowflake_users(cache, snowflakeCursor):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        username = user["name"]
        # this is a passing check
        if user["default_role"] not in ["ACCOUNTADMIN","SECURITYADMIN"] or user["default_role"] is None and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/snowflake-admin-default-role-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.5] Snowflake users should not be assigned the ACCOUNTADMIN or SECURITYADMIN role as the default role",
                "Description": f"Snowflake user {username} does has not have the ACCOUNTADMIN nor the SECURITYADMIN role as their default role.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on assinging default roles and the rationale for not assigning ACCOUNTADMIN or SECURITYADMIN as the default rolerefer to the Avoid using the ACCOUNTADMIN role to create objects section of the Snowflake Documentation Portal.",
                        "Url": "https://docs.snowflake.com/en/user-guide/security-access-control-considerations#avoid-using-the-accountadmin-role-to-create-objects"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.12"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        # this is a failing check
        if user["default_role"] in ["ACCOUNTADMIN","SECURITYADMIN"] and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/snowflake-admin-default-role-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.5] Snowflake users should not be assigned the ACCOUNTADMIN or SECURITYADMIN role as the default role",
                "Description": f"Snowflake user {username} has either the ACCOUNTADMIN or SECURITYADMIN role as their default role. The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is intended for performing initial setup and managing account-level objects. SECURITYADMIN role can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles should be used for performing daily non-administrative tasks in a Snowflake account. Instead, users should be assigned custom roles containing only those privileges that are necessary for successfully completing their job responsibilities. When ACCOUNTADMIN is not set as a default user role, it forces account administrators to explicitly change their role to ACCOUNTADMIN each time they log in. This can help make account administrators aware of the purpose of roles in the system, prevent them from inadvertently using the ACCOUNTADMIN role for non-administrative tasks, and encourage them to change to the appropriate role for a given task. Same logic applies to the SECURITYADMIN role. For more information on user management best practices refer to the Snowflake documentation.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on assinging default roles and the rationale for not assigning ACCOUNTADMIN or SECURITYADMIN as the default rolerefer to the Avoid using the ACCOUNTADMIN role to create objects section of the Snowflake Documentation Portal.",
                        "Url": "https://docs.snowflake.com/en/user-guide/security-access-control-considerations#avoid-using-the-accountadmin-role-to-create-objects"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "CIS Snowflake Foundations Benchmark V1.0.0 1.12"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("snowflake.users")
def snowflake_logins_without_mfa_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor
) -> dict:
    """[Snowflake.Users.6] Snowflake users should be monitored for logins without MFA"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    # Get all of the users
    for user in get_snowflake_users(cache, snowflakeCursor):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        username = user["name"]

        # Hey, we prepoulate the MFA status in the user object so we can just check it here
        loggedInWithoutMfa = user["logged_on_without_mfa"]
        timesLoggedInWithoutMfa = user["total_logons_without_mfa"]

        # this is a passing check
        if loggedInWithoutMfa is False and user["has_password"] is True and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/snowflake-logins-without-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.6] Snowflake users should be monitored for logins without MFA",
                "Description": f"Snowflake user {username} has not logged in without MFA. This check does not take into account if users have *never* logged in nor does it take into account if users have MFA enabled. This check relies on data stored in the LOGON_HISTORY view and may not be up-to-date.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on MFA best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                        "Url": "https://community.snowflake.com/s/article/Snowflake-Security-Overview-and-Best-Practices?mkt_tok=MjUyLVJGTy0yMjcAAAGTVPcnsobib0St0CwRwVZ4sfwHPicq12DnL_MX_bz-yG4OgkADmIh6ll3PcRhIqFeezBwdFSNL-ipp9vJHUV6hRiKUK2b-0f5_HGpkwz7pTG2_w6cO9Q"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "CIS Snowflake Foundations Benchmark V1.0.0 2.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        # this is a failing check
        if loggedInWithoutMfa is True and user["has_password"] is True and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/snowflake-logins-without-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.6] Snowflake users should be monitored for logins without MFA",
                "Description": f"Snowflake user {username} has logged in without MFA {timesLoggedInWithoutMfa} times. This check relies on data stored in the LOGON_HISTORY view and includes at least a year of logins, hence the lower severity level. Multi-factor authentication (MFA) is a security control used to add an additional layer of login security. It works by requiring the user to present two or more proofs (factors) of user identity. An MFA example would be requiring a password and a verification code delivered to the user's phone during user sign-in. MFA mitigates security threats of users creating weak passwords and user passwords being stolen or accidentally leaked. For more information on MFA best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on MFA best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                        "Url": "https://community.snowflake.com/s/article/Snowflake-Security-Overview-and-Best-Practices?mkt_tok=MjUyLVJGTy0yMjcAAAGTVPcnsobib0St0CwRwVZ4sfwHPicq12DnL_MX_bz-yG4OgkADmIh6ll3PcRhIqFeezBwdFSNL-ipp9vJHUV6hRiKUK2b-0f5_HGpkwz7pTG2_w6cO9Q"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "CIS Snowflake Foundations Benchmark V1.0.0 2.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("snowflake.users")
def snowflake_admin_password_users_yearly_password_rotation_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor
) -> dict:
    """[Snowflake.Users.7] Snowflake users with any admin role assigned should have their password rotated yearly"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    # Get all of the users
    for user in get_snowflake_users(cache, snowflakeCursor):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        username = user["name"]

        # Use the "is_admin" field to determine if the user is an admin and the "password_last_set_time" field (ISO-8061) to determine if the password has been rotated in the last year
        rotatedInLastYear = True
        isAdmin = user["is_admin"]
        passwordLastSetTime = datetime.fromisoformat(user["password_last_set_time"])
        currentTime = datetime.now(UTC)
        daysAgo = currentTime - timedelta(days=365)
        if passwordLastSetTime < daysAgo:
            rotatedInLastYear = False
        
        # this is a passing check
        if rotatedInLastYear is True and isAdmin is True and user["has_password"] is True and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/snowflake-admins-yearly-passowrd-rotation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.7] Snowflake users with any admin role assigned should have their password rotated yearly",
                "Description": f"Snowflake user {username} has an admin role assigned and has rotated their password in the last year. This check does not account for custom assigned roles, only the built-in Snowflake admin roles: ACCOUNTADMIN, ORGADMIN, SECURITYADMIN, or SYSADMIN. This check also only checks if there is a password set for the user, as 'service accounts' do not have passwords and do not need to be rotated.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on security best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                        "Url": "https://community.snowflake.com/s/article/Snowflake-Security-Overview-and-Best-Practices?mkt_tok=MjUyLVJGTy0yMjcAAAGTVPcnsobib0St0CwRwVZ4sfwHPicq12DnL_MX_bz-yG4OgkADmIh6ll3PcRhIqFeezBwdFSNL-ipp9vJHUV6hRiKUK2b-0f5_HGpkwz7pTG2_w6cO9Q"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        # this is a failing check
        if rotatedInLastYear is False and isAdmin is True and user["has_password"] is True and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/snowflake-admins-yearly-passowrd-rotation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.7] Snowflake users with any admin role assigned should have their password rotated yearly",
                "Description": f"Snowflake user {username} has an admin role assigned and has not rotated their password in the last year. This check does not account for custom assigned roles, only the built-in Snowflake admin roles: ACCOUNTADMIN, ORGADMIN, SECURITYADMIN, or SYSADMIN. This check also only checks if there is a password set for the user, as 'service accounts' do not have passwords and do not need to be rotated. Password rotation is a security best practice that helps prevent unauthorized access to systems and data. For more information on security best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on security best practices for users in Snowflake refer to the community post Snowflake Security Overview and Best Practices in the Snowflake Community Portal.",
                        "Url": "https://community.snowflake.com/s/article/Snowflake-Security-Overview-and-Best-Practices?mkt_tok=MjUyLVJGTy0yMjcAAAGTVPcnsobib0St0CwRwVZ4sfwHPicq12DnL_MX_bz-yG4OgkADmIh6ll3PcRhIqFeezBwdFSNL-ipp9vJHUV6hRiKUK2b-0f5_HGpkwz7pTG2_w6cO9Q"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "RESOLVED"
            }
            yield finding

@registry.register_check("snowflake.users")
def snowflake_bypass_mfa_review_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor
) -> dict:
    """[Snowflake.Users.8] Snowflake users allowed to bypass MFA should be reviewed"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    # Get all of the users
    for user in get_snowflake_users(cache, snowflakeCursor):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        username = user["name"]

        # Use the "bypass_mfa_until" field (ISO-8061) to determine if the user is allowed to bypass MFA by checking if the date is in the future - only perform this check for password users with MFA enabled
        mfaBypass = False
        if user["ext_authn_duo"] is True and user["has_password"] is True:
            if user["bypass_mfa_until"] is not None:
                bypassMfaUntil = datetime.fromisoformat(user["bypass_mfa_until"])
                currentTime = datetime.now(UTC)
                if bypassMfaUntil > currentTime:
                    mfaBypass = True
        
        # this is a passing check
        if mfaBypass is False and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/snowflake-user-mfa-bypass-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.8] Snowflake users allowed to bypass MFA should be reviewed",
                "Description": f"Snowflake user {username} is not allowed to bypass MFA or they do not have MFA or a Password enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on managing MFA and bypass for users in Snowflake refer to the Managing MFA for an account and users section of the Snowflake Documentation Portal.",
                        "Url": "https://docs.snowflake.com/en/user-guide/security-mfa"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        # this is a failing check
        if mfaBypass is True and user["deleted_on"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snowflakeAccountId}/{username}/snowflake-user-mfa-bypass-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{snowflakeAccountId}/{username}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Snowflake.Users.8] Snowflake users allowed to bypass MFA should be reviewed",
                "Description": f"Snowflake user {username} has MFA assigned and is allowed to bypass MFA. When MFA is enabled, users are required to provide two or more verification factors to access their account. Allowing users to bypass MFA can increase the risk of unauthorized access to your Snowflake account. While there are some administrative reasons to bypass MFA, these users should be reviewed to ensure that they are not a security risk.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on managing MFA and bypass for users in Snowflake refer to the Managing MFA for an account and users section of the Snowflake Documentation Portal.",
                        "Url": "https://docs.snowflake.com/en/user-guide/security-mfa"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Snowflake",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": snowflakeAccountId,
                    "AssetRegion": snowflakeRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Snowflake Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SnowflakeUser",
                        "Id": username,
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
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

# EOF