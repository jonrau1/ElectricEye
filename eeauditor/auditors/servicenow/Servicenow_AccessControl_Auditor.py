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
import json
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

@registry.register_check("servicenow.access_control")
def servicenow_sspm_user_session_allow_unsanitzed_messages_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.AccessControl.1] Instance should block access to GlideSystemUserSession scriptable API unsanitized messages
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.sandbox.usersession.allow_unsanitized_messages"
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
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.AccessControl.1] Instance should block access to GlideSystemUserSession scriptable API unsanitized messages",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not block access to GlideSystemUserSession scriptable API unsanitized messages. The client callable GlideSystemUserSessionSandbox scriptable API exposes GlideSystemUserSession's addErrorMessageNoSanitization and addInfoMessageNoSanitization methods to the javascript sandbox. This allows all users to call this method via script. When 'glide.sandbox.usersession.allow_unsanitized_messages' is set to 'true' a sandboxed user session is allowed to call information or error messages without sanitization. A warning will be logged when the message is called. When set to false, the call is not allowed. Without appropriate sanitization, potentially dangerous content may be accessed and the unsanitized error function is available to script. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Access to GlideSystemUserSession scriptable API section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/Access-GlideSystemUserSession-scriptable-API.html",
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
            "Title": "[SSPM.Servicenow.AccessControl.1] Instance should block access to GlideSystemUserSession scriptable API unsanitized messages",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} blocks access to GlideSystemUserSession scriptable API unsanitized messages.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Access to GlideSystemUserSession scriptable API section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/Access-GlideSystemUserSession-scriptable-API.html",
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

@registry.register_check("servicenow.access_control")
def servicenow_sspm_sysappmodule_script_exec_restriction_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.AccessControl.2] Instance should restrict authorization for script execution from the 'sys_app_module' table to specified roles
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.script_processor.authorized_script_module_role"
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
    if propertyValue != "":
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
            "Title": "[SSPM.Servicenow.AccessControl.2] Instance should restrict authorization for script execution from the 'sys_app_module' table to specified roles",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not restrict authorization for script execution from the 'sys_app_module' table to specified roles. Use the glide.script_processor.authorized_script_module_role property to restrict the usage of running scripts from sys_app_module table to the defined role within the property. This property will restrict all system users of running any script from the sys_app_module unless they have the role specified within the property. Use the glide.script_processor.authorized_script_module_role property to specify the role that can run scripts. Without appropriate authorization configured on script requests, unauthorized users may access sensitive content/data on the instance. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Authorization for script execution section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/authorization-script-execution.html",
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
            "Title": "[SSPM.Servicenow.AccessControl.2] Instance should restrict authorization for script execution from the 'sys_app_module' table to specified roles",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} restricts authorization for script execution from the 'sys_app_module' table to specified roles.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Authorization for script execution section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/authorization-script-execution.html",
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

@registry.register_check("servicenow.access_control")
def servicenow_sspm_jsonv2_enforce_basic_auth_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.AccessControl.3] Instance should enforce basic authentication for JSONv2 requests
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.basicauth.required.jsonv2"
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
            "Title": "[SSPM.Servicenow.AccessControl.3] Instance should enforce basic authentication for JSONv2 requests",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not enforce basic authentication for JSONv2 requests. Use the 'glide.basicauth.required.jsonv2' property to designate if incoming JSONv2 requests should require basic authorization. Without appropriate authorization configured on the data source JSON requests, an unauthorized user can access sensitive content/data on the target instance. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Basic auth: JSONv2 requests (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/basic-auth-jsonv2-requests.html",
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
            "Title": "[SSPM.Servicenow.AccessControl.3] Instance should enforce basic authentication for JSONv2 requests",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} enforces basic authentication for JSONv2 requests.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Basic auth: JSONv2 requests (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/basic-auth-jsonv2-requests.html",
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

@registry.register_check("servicenow.access_control")
def servicenow_sspm_soap_enforce_basic_auth_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.AccessControl.4] Instance should enforce basic authentication for SOAP requests
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.basicauth.required.soap"
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
            "Title": "[SSPM.Servicenow.AccessControl.4] Instance should enforce basic authentication for SOAP requests",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not enforce basic authentication for SOAP requests. Use the 'glide.basicauth.required.soap' property to designate if incoming SOAP requests should require basic authorization. Without appropriate authorization configured on the data source SOAP requests, an unauthorized user can access sensitive content/data on the target instance. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Basic auth: SOAP requests (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/basic-auth-soap-requests.html",
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
            "Title": "[SSPM.Servicenow.AccessControl.4] Instance should enforce basic authentication for SOAP requests",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} enforces basic authentication for SOAP requests.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Basic auth: SOAP requests (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/basic-auth-soap-requests.html",
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

@registry.register_check("servicenow.access_control")
def servicenow_sspm_block_access_for_delegated_dev_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.AccessControl.5] Instance should block access to the 'sys_user_has_role' table for delegated developer grant roles
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "com.glide.sys.security.delegateddev.block_grant_roles"
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
            "Title": "[SSPM.Servicenow.AccessControl.5] Instance should block access to the 'sys_user_has_role' table for delegated developer grant roles",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not block access to the 'sys_user_has_role' table for delegated developer grant roles. This configuration affects access for delegated developers that are updating user roles through script. When the configuration is compliant, the developer will not be able to update or insert records into the table sys_user_has_role without also the user_admin role. The value of this property affects whether a delegated developer is allowed to grant or receive unexpected access to functionality in the instance. When the property contains roles, only those roles may execute script modules. Without appropriate authorization, unauthorized users may access sensitive content/data on the instance. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Block access for delegated developer section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/block-access-delegated-developers.html",
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
            "Title": "[SSPM.Servicenow.AccessControl.5] Instance should block access to the 'sys_user_has_role' table for delegated developer grant roles",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} blocks access to the 'sys_user_has_role' table for delegated developer grant roles.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Block access for delegated developer section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/block-access-delegated-developers.html",
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

# TODO: CONTEXTUAL SECURITY: ROLE MGMT PLUGIN CHECK | https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/contextual-security.html

@registry.register_check("servicenow.access_control")
def servicenow_sspm_csv_enforce_basic_auth_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.AccessControl.7] Instance should enforce basic authentication for CSV requests
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.basicauth.required.csv"
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
            "Title": "[SSPM.Servicenow.AccessControl.7] Instance should enforce basic authentication for CSV requests",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not enforce basic authentication for CSV requests. Use the 'glide.basicauth.required.csv' property to designate if incoming CSV (Comma-Separated Values) requests should require basic authentication. Without appropriate authorization configured on the incoming CSV requests, an unauthorized user can get access to sensitive content/data on the target instance. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the CSV request authorization (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/csv-request-authorization.html",
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
            "Title": "[SSPM.Servicenow.AccessControl.7] Instance should enforce basic authentication for CSV requests",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} enforces basic authentication for CSV requests.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the CSV request authorization (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/csv-request-authorization.html",
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

@registry.register_check("servicenow.access_control")
def servicenow_sspm_acl_default_deny_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.AccessControl.8] Instance should be configured to deny access to objects that match wildcard table ACL rules by default
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.sm.default_mode"
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
    if propertyValue != "deny":
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
            "Title": "[SSPM.Servicenow.AccessControl.8] Instance should be configured to deny access to objects that match wildcard table ACL rules by default",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to deny access to objects that match wildcard table ACL rules by default. Use the glide.sm.default_mode property to control the default behavior of security manager when it finds that existing ACL rules are a part of wildcard table ACL rules. When the High Security Settings (com.glide.high_security) plugin is activated during initial instance installation, it creates this property, and wildcard ACL rules come into existence. To provide role-based access to system tables, these rules control a significant number of ACLs and most common record-based operations. Unless you use the High Security plugin with default deny option enabled, many tables are not protected. The Now Platform uses a default deny security model that prevents non-administrator users from accessing objects unless they meet a matching ACL rule. Using this model, it removes many attack vectors, such as insecure scripts. Without the proper setting, Non-administrator users can access objects that match the wildcard table ACL rules. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Default deny (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/default-deny.html",
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
            "Title": "[SSPM.Servicenow.AccessControl.8] Instance should be configured to deny access to objects that match wildcard table ACL rules by default",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to deny access to objects that match wildcard table ACL rules by default.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Default deny (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/default-deny.html",
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

@registry.register_check("servicenow.access_control")
def servicenow_sspm_double_check_inbound_transactions_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.AccessControl.9] Instance should be configured to double check security on from submission inbound transactions
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.security.strict.updates"
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
            "Title": "[SSPM.Servicenow.AccessControl.9] Instance should be configured to double check security on from submission inbound transactions",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to double check security on from submission inbound transactions. Use the 'glide.security.strict.updates' property to enable double-checking of security on inbound transactions during form submission. When you set this property to true, it adds an extra layer of table validation before a form renders in the browser. You should always check access request when transactions happen between two zones. This operation checks for permissions when the form is requested and before form rendering happens. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Double check inbound transactions (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/double-check-inbound-transactions.html",
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
            "Title": "[SSPM.Servicenow.AccessControl.9] Instance should be configured to double check security on from submission inbound transactions",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to double check security on from submission inbound transactions.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Double check inbound transactions (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/double-check-inbound-transactions.html",
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

# END??