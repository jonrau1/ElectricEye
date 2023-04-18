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
        return response
    
    # Will need to create the pysnow.Client object everywhere - doesn't appear to be thread-safe
    snow = pysnow.Client(
        instance=SNOW_INSTANCE_NAME,
        user=SNOW_SSPM_USERNAME,
        password=SNOW_SSPM_PASSWORD
    )

    sysPropResource = snow.resource(api_path='/table/sys_properties')
    sysPropsRaw = sysPropResource.get().all()
    # jack with the JSON
    #sysProps = json.dumps(json.loads(sysPropsRaw))
    
    cache["get_servicenow_sys_properties"] = sysPropsRaw

    return cache["get_servicenow_sys_properties"]

@registry.register_check("servicenow.access_control")
def servicenow_sspm_user_session_allow_unsanitzed_messages_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.AccessControl.1] Instance should block access to GlideSystemUserSession scriptable API unsanitized messages
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for sysprop in get_servicenow_sys_properties(cache):
        propertyName = str(sysprop["name"])
        propertyValue = str(sysprop["value"])
        # NOTE: This is where you match the sys_property you want to evaluate in reverse by continuing the loop when the 
        # value does not match what we want - should be faster than looking up a match. At the end of value evaluation
        # you will `break` the loop
        if propertyName != "glide.sandbox.usersession.allow_unsanitized_messages":
            continue
        else:
            # NOTE: At this point you can bring in additional parsed info - we don't need to keep this shit in memory the whole loop
            propDescription = str(sysprop["description"]).replace("\n    ", "")
            propId = str(sysprop["sys_id"])
            propCreatedOn = str(sysprop["sys_created_on"])
            propCreatedBy = str(sysprop["sys_created_by"])
            propUpdatedOn = str(sysprop["sys_updated_on"])
            propUpdatedBy = str(sysprop["sys_updated_by"])
            propScope = str(sysprop["sys_scope"]["value"])
            # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
            # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
            # are not a simple Boolean expression
            if propertyValue != "false":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/glide.sandbox.usersession.allow_unsanitized_messages/check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/glide.sandbox.usersession.allow_unsanitized_messages/check",
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
                            "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/glide.sandbox.usersession.allow_unsanitized_messages",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "ServicenowInstance": SNOW_INSTANCE_NAME,
                                    "SysId": propId,
                                    "PropertyName": propertyName,
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
                    "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/glide.sandbox.usersession.allow_unsanitized_messages/check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/glide.sandbox.usersession.allow_unsanitized_messages/check",
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
                            "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/glide.sandbox.usersession.allow_unsanitized_messages",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "ServicenowInstance": SNOW_INSTANCE_NAME,
                                    "SysId": propId,
                                    "PropertyName": propertyName,
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
            break

@registry.register_check("servicenow.access_control")
def servicenow_sspm_user_session_allow_unsanitzed_messages_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.AccessControl.2] Instance should enforce basic authentication for JSONv2 requests
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for sysprop in get_servicenow_sys_properties(cache):
        propertyName = str(sysprop["name"])
        propertyValue = str(sysprop["value"])
        # NOTE: This is where you match the sys_property you want to evaluate in reverse by continuing the loop when the 
        # value does not match what we want - should be faster than looking up a match. At the end of value evaluation
        # you will `break` the loop
        if propertyName != "glide.basicauth.required.jsonv2":
            continue
        else:
            # NOTE: At this point you can bring in additional parsed info - we don't need to keep this shit in memory the whole loop
            propDescription = str(sysprop["description"]).replace("\n    ", "")
            propId = str(sysprop["sys_id"])
            propCreatedOn = str(sysprop["sys_created_on"])
            propCreatedBy = str(sysprop["sys_created_by"])
            propUpdatedOn = str(sysprop["sys_updated_on"])
            propUpdatedBy = str(sysprop["sys_updated_by"])
            propScope = str(sysprop["sys_scope"]["value"])
            # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
            # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
            # are not a simple Boolean expression
            if propertyValue != "true":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/glide.basicauth.required.jsonv2/check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/glide.basicauth.required.jsonv2/check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[SSPM.Servicenow.AccessControl.2] Instance should enforce basic authentication for JSONv2 requests",
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
                            "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/glide.basicauth.required.jsonv2",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "ServicenowInstance": SNOW_INSTANCE_NAME,
                                    "SysId": propId,
                                    "PropertyName": propertyName,
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
                    "Id": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/glide.basicauth.required.jsonv2/check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/sys_properties/glide.basicauth.required.jsonv2/check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[SSPM.Servicenow.AccessControl.2] Instance should enforce basic authentication for JSONv2 requests",
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
                            "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/glide.basicauth.required.jsonv2",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "ServicenowInstance": SNOW_INSTANCE_NAME,
                                    "SysId": propId,
                                    "PropertyName": propertyName,
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
            break

# END??