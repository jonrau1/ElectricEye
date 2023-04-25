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

def get_servicenow_sys_properties(cache: dict):
    """
    Pulls the entire Systems Properties table
    """
    response = cache.get("get_servicenow_sys_properties")
    if response:
        print("servicenow.access_control cache hit!")
        return response
    
    # Will need to create the pysnow.Client object everywhere - doesn't appear to be thread-safe
    snow = pysnow.Client(
        instance=SNOW_INSTANCE_NAME,
        user=SNOW_SSPM_USERNAME,
        password=SNOW_SSPM_PASSWORD
    )

    sysPropResource = snow.resource(api_path='/table/sys_properties')
    sysProps = sysPropResource.get().all()

    cache["get_servicenow_sys_properties"] = sysProps

    return cache["get_servicenow_sys_properties"]

# NOTE: Dict search next() iterator thingy from: https://stackoverflow.com/questions/8653516/search-a-list-of-dictionaries-in-python

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_absolute_session_timeout_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.1] Instance should configure an absolute session timeout lower than the default 30 days
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.user_cookie.max_life_span_in_days"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression

    # For this check we need to convert value to an int for the comparison - keeping the tradition of the first finding being a FAIL
    # if for some reason there is a type error from the property not being set - we will set it to the default (which fails)
    try:
        propertyInt = int(propertyValue)
    except ValueError:
        propertyInt = 30
    if propertyInt >= 30:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.1] Instance should configure an absolute session timeout lower than the default 30 days",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not configure an absolute session timeout lower than the default 30 days. Use the 'glide.ui.user_cookie.max_life_span_in_days' property to set a maximum cap for a valid user session to expire before forcing a user to reauthenticate into the instance. It enables the user cookie to be valid for the duration of specified days, starting when the cookie was first issued. The default value is 30 days, and the maximum cap is at 365 days. The user cookies being active for an indefinite amount of time is a security risk and should expire on a time-based configuration. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Absolute session timeout (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/absolute-session-timeout.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.1] Instance should configure an absolute session timeout lower than the default 30 days",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does configure an absolute session timeout lower than the default 30 days.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Absolute session timeout (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/absolute-session-timeout.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_anti_csrf_token_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.2] Instance should have an Anti-CSRF token enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.security.use_csrf_token"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "true":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.2] Instance should have an Anti-CSRF token enabled",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not have an Anti-CSRF token enabled. Use the 'glide.security.use_csrf_token' property to ensure the use of a secure token to identify and validates incoming requests, which in turn are used to prevent these attacks. Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request. CSRF is a significant security risk that violates the integrity of the instance data. An attacker can launch the CSRF attack by abusing the trust of an instance user. With the help of social engineering attacks, a user can submit a malformed request on behalf of the attacker on the instance. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Anti-CSRF token (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/anti-csrf-token.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.2] Instance should have an Anti-CSRF token enabled",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does have an Anti-CSRF token enabled.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Anti-CSRF token (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/anti-csrf-token.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_cookies_http_only_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.3] Instance should enable the HTTPOnly attribute for sensitive cookies
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.cookies.http_only"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "true":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.3] Instance should enable the HTTPOnly attribute for sensitive cookies",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not enable the HTTPOnly attribute for sensitive cookies. Use the 'glide.cookies.http_only' property to enable the HTTPOnly attribute for sensitive cookies. Use the HTTPOnly attribute to prevent attacks, such as cross-site scripting, because it doesn't allow access to the cookie using a client-side script, such as JavaScript. It does not eliminate cross site scripting risks but does eliminate some exploitation vectors. Session cookies in the application authenticate an end user and provide implicit access permissions on the application. That means there is a need to secure them from being stolen or exported. HTTP Only flags protect the session cookies from JavaScript injections or cross site scripting vulnerabilities stealing them. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Cookies HTTP only (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/cookies-http-only.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.3] Instance should enable the HTTPOnly attribute for sensitive cookies",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does enable the HTTPOnly attribute for sensitive cookies.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Cookies HTTP only (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/cookies-http-only.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_csrf_strict_validation_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.4] Instance should enable strict validation for Anti-CSRF tokens
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.security.csrf.strict.validation.mode"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "true":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.4] Instance should enable strict validation for Anti-CSRF tokens",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not enable strict validation for Anti-CSRF tokens. Use the 'glide.security.csrf.strict.validation.mode' property to enable CSRF token strict validation. If the CSRF token doesn't match, it prevents resubmission of the request. Cross site Request Forgery is a significant security risk that violates the integrity of the instance data. An attacker can launch the CSRF attack on any instance user by abusing the trust of the instance user. With the help of social engineering attacks, a user can submit a malformed request to the instance on behalf of the attacker. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the CSRF strict validation (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/csrf-strict-validation.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.4] Instance should enable strict validation for Anti-CSRF tokens",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does enable strict validation for Anti-CSRF tokens.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the CSRF strict validation (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/csrf-strict-validation.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_disable_passwordless_authentication_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.5] Instance should prevent users from logging in without a password
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.login.no_blank_password"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "true":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.5] Instance should prevent users from logging in without a password",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not prevent users from logging in without a password. Use the 'glide.login.no_blank_password' property to prevent users from logging in to the Now Platform with blank passwords, or by leaving the Password field empty. Even if the admin purposefully assigns an empty value or blank password in user records, a user can't log in without providing a value in the Password field. An attacker is able to log in to the instance with the default usernames, or by specific individual/group (usually firstname.lastname) without any password. Doing so is viewed as a critical security risk, because it would enable a public user to violate the confidentiality and integrity of the instance data. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Disable password-less authentication (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/disable-password-less-authentication.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.5] Instance should prevent users from logging in without a password",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does prevent users from logging in without a password.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Disable password-less authentication (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/disable-password-less-authentication.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_enable_mfa_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.6] Instance should have Multi-Factor Authentication (MFA) enabled for the instance
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.authenticate.multifactor"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "true":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "CRITICAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.6] Instance should have Multi-Factor Authentication (MFA) enabled for the instance",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not have Multi-Factor Authentication (MFA) enabled for the instance. Use the 'glide.authenticate.multifactor' property to enable Multi-Factor Authentication (MFA) in the instance. MFA is a security requirement that requires a user to enter more than one set of credentials to authenticate to an instance. If this property is not enabled, there is a risk of unauthorized access to sensitive data. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Enable multi-factor authentication (MFA) (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/multi-factor-authentication.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.6] Instance should have Multi-Factor Authentication (MFA) enabled for the instance",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does have Multi-Factor Authentication (MFA) enabled for the instance.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Enable multi-factor authentication (MFA) (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/multi-factor-authentication.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_enable_password_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.7] Instance should enable strong password policy validation for users changing their password
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.enable.password_policy"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "true":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.7] Instance should enable strong password policy validation for users changing their password",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not enable strong password policy validation for users changing their password. Use the 'glide.enable.password_policy' property to enable password policy checks whenever a user changes their password using the user interface. Without a password policy, a user can create a weak password which increases the likelihood of an adversary gaining access to the instance. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Enable Password Reset Policy Checks (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/enforce-strong-passwords.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.7] Instance should enable strong password policy validation for users changing their password",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does enable strong password policy validation for users changing their password.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Enable Password Reset Policy Checks (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/enforce-strong-passwords.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_disable_password_autocomplete_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.8] Instance should be configured to disable password auto-complete on browsers
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.login.autocomplete"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "false":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.8] Instance should be configured to disable password auto-complete on browsers",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to disable password auto-complete on browsers. Use the 'glide.login.autocomplete' property to enable browsers to use auto-complete on password fields in login forms. User authentication fields should be validated and should never let the client-side caching to happen. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Password field auto-complete (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/password-field-autocomplete.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.8] Instance should be configured to disable password auto-complete on browsers",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to disable password auto-complete on browsers.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Password field auto-complete (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/password-field-autocomplete.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_remove_rememberme_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.9] Instance should be configured to remove the 'Remember Me' check box from the login page
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.forgetme"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "true":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.9] Instance should be configured to remove the 'Remember Me' check box from the login page",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to remove the 'Remember Me' check box from the login page. Use the 'glide.ui.forgetme' property to remove the Remember Me check box from the login page to prevent login information from being cached. When you select the Remember me check box at login, an extra cookie is stored on the user's computer. It poses a security risk as it allows the user session to be active until they deliberately log out. The likelihood of an attack for this scenario increases when the end user has left the browser unattended, or if it is compromised from a different attack. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Remove remember me (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/remove-remember-me.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.9] Instance should be configured to remove the 'Remember Me' check box from the login page",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to remove the 'Remember Me' check box from the login page.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Remove remember me (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/remove-remember-me.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_rotate_http_session_ids_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.10] Instance should enable rotation of HTTP session identifiers
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.rotate_sessions"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "true":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.10] Instance should enable rotation of HTTP session identifiers",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not enable rotation of HTTP session identifiers. Use the 'glide.ui.rotate_sessions' property to enable rotation of the HTTP session identifiers to reduce security vulnerabilities. If an unauthenticated user's session ID doesn't change after authentication, a web application is vulnerable to a session fixation attack. A malicious user could start an unauthenticated session and give the associated session ID to the victim. Once the victim authenticates, the malicious user now shares that authenticated session. SessionID is deemed as sensitive data and should be secure by default. Session Rotation is a security control that enforces the alteration of sessionID whenever the user navigates from unauthenticated pages to authenticate pages. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Rotate HTTP session identifiers (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/rotate-http-session-identifiers.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.10] Instance should enable rotation of HTTP session identifiers",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does enable rotation of HTTP session identifiers.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Rotate HTTP session identifiers (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/rotate-http-session-identifiers.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_secure_session_cookies_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.11] Instance should be configured to reject sessions for improperly formatted cookies
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.secure_cookies"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "true":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.11] Instance should be configured to reject sessions for improperly formatted cookies",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to reject sessions for improperly formatted cookies. Use the glide.ui.secure_cookies property to require properly formatted cookies. When you set the property is to true, your instance will reject a session if the associated cookie is not in the expected format. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Secure session cookies (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/secure-session-cookies.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.11] Instance should be configured to reject sessions for improperly formatted cookies",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to reject sessions for improperly formatted cookies.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Secure session cookies (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/secure-session-cookies.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_security_referral_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.12] Instance should configure a strong security referral policy to control what referrer data must be sent in HTTP response headers
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # For the SRP check, this list contains the reccomended values
    reccomendedSecurityReferralPolicies = [
        "default",
        "same-origin",
        "origin",
        "origin-when-cross-origin"
    ]

    # Name of the property to evaluate against
    evalTarget = "com.glide.security.referrerpolicy"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue not in reccomendedSecurityReferralPolicies:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.12] Instance should configure a strong security referral policy to control what referrer data must be sent in HTTP response headers",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not configure a strong security referral policy to control what referrer data must be sent in HTTP response headers. Use the 'com.glide.security.referrerpolicy' property to control what referrer data should be sent in HTTP response headers when Now Platform pages sends requests for data. The Referrer-Policy value in an HTTP header controls what referrer information should be included with data requests. Setting this property value to 'no-referrer-when-downgrade' does not ensure a good level of security for your instance. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Security referral policy (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/security-referral-policy.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.12] Instance should configure a strong security referral policy to control what referrer data must be sent in HTTP response headers",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does configure a strong security referral policy to control what referrer data must be sent in HTTP response headers.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Security referral policy (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/security-referral-policy.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_session_activity_timeout_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.13] Instance should configure a strong session activity timeout threshold
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.session_timeout"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression

    # For this timeout check, conversion needs to happen to an int
    if propertyValue == "NOT_CONFIGURED":
        seshTimeout = 61
    else:
        try:
            seshTimeout = int(propertyValue)
        except Exception:
            seshTimeout = 61
    if seshTimeout >= 61:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.13] Instance should configure a strong session activity timeout threshold",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not configure a strong session activity timeout threshold. Use the 'glide.ui.session_timeout' property to designate, in minutes, activity timeout value. 60 minutes is the recommended value, but this value may vary depending on functionality and security requirement. Do not set this value to more than one day. User sessions being active for indefinite amount of time is a security risk and should expire on a time-based configuration. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Session activity timeout (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/session-activity-timeout.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.13] Instance should configure a strong session activity timeout threshold",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does configure a strong session activity timeout threshold.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Session activity timeout (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/session-activity-timeout.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.sessionmanagement")
def servicenow_sspm_session_window_timeout_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SessionManagement.14] Instance should configure a strong session window timeout threshold for Remember Me cookies
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.user_cookie.life_span_in_days"
    # Get cached props
    sysPropCache = get_servicenow_sys_properties(cache)

    # There should not ever be a duplicate system property, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    propFinder = next((sysprop for sysprop in sysPropCache if sysprop["name"] == evalTarget), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if propFinder == False:
        propertyValue = "NOT_CONFIGURED"
        propDescription = ""
        propId = ""
        propCreatedOn = ""
        propCreatedBy = ""
        propUpdatedOn = ""
        propUpdatedBy = ""
        propScope = ""
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])        
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression

    # For this timeout check, conversion needs to happen to an int
    if propertyValue == "NOT_CONFIGURED":
        seshTimeout = 30
    else:
        try:
            seshTimeout = int(propertyValue)
        except Exception:
            seshTimeout = 30
    if seshTimeout > 15:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.14] Instance should configure a strong session window timeout threshold for Remember Me cookies",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not configure a strong session window timeout threshold for Remember Me cookies. Use the 'glide.ui.user_cookie.life_span_in_days' property to set the expiration time period for the Remember Me cookie. The default value is 15 days and the maximum cap is at 30 days. The user cookies being active for an indefinite amount of time is a security risk and should expire on a time-based configuration. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Session window timeout (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/session-window-timeout.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SessionManagement.14] Instance should configure a strong session window timeout threshold for Remember Me cookies",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does configure a strong session window timeout threshold for Remember Me cookies.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Session window timeout (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/session-window-timeout.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Servicenow",
                "AssetClass": "Management & Governance",
                "AssetService": "Servicenow System Properties",
                "AssetType": "Servicenow Instance"
            },
            "Resources": [
                {
                    "Type": "ServicenowInstance",
                    "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": propId,
                            "PropertyName": evalTarget,
                            "PropertyValue": propertyValue,
                            "Description": propDescription,
                            "CreatedBy": propCreatedBy,
                            "CreatedOn": propCreatedOn,
                            "UpdatedBy": propUpdatedBy,
                            "UpdatedOn": propUpdatedOn,
                            "Scope": propScope
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.PT-3",
                    "NIST SP 800-53 AC-3",
                    "NIST SP 800-53 CM-7",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.6.2.2", 
                    "ISO 27001:2013 A.9.1.2",
                    "ISO 27001:2013 A.9.4.1",
                    "ISO 27001:2013 A.9.4.4",
                    "ISO 27001:2013 A.9.4.5",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3",
                    "ISO 27001:2013 A.18.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

## END???