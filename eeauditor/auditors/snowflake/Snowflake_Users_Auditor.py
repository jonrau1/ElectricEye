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

logger = logging.getLogger("AwsEc2Auditor")

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
            logger.warning("User %s is inactive or roles are unable to be retrieved.", username)
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
        logger.warning("Exception encountered while trying to get users: %s", e)
    
    cache["get_snowflake_users"] = snowflakeUsers

    return cache["get_snowflake_users"]