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
import base64
import json

registry = CheckRegister()

SNOW_INSTANCE_NAME = os.environ["SNOW_INSTANCE_NAME"]
SNOW_INSTANCE_REGION = os.environ["SNOW_INSTANCE_REGION"]
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_disallow_embedded_html_code_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.1] Instance should disable support for embedding HTML code created using the [code] tag
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.security.allow_codetag"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Servicenow.InputValidation.1] Instance should disable support for embedding HTML code created using the [code] tag",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not disable support for embedding HTML code created using the [code] tag. Use the 'glide.ui.security.allow_codetag' property to disable support for embedding HTML code created using the [code] tag. Input validation must occur in the application to defend against cross-site scripting attacks. These attacks enable foreign scripts to execute on a user session in the logged in browser's context. Attackers can use it to steal session information and sensitive data. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Allow embedded HTML code (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/allow-embedded-html-code.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.1] Instance should disable support for embedding HTML code created using the [code] tag",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does disable support for embedding HTML code created using the [code] tag.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Allow embedded HTML code (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/allow-embedded-html-code.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_disallow_js_tags_embedded_html_code_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.2] Instance should disable support for embedding HTML JavaScript code created using the [code] tag
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.security.codetag.allow_script"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Title": "[Servicenow.InputValidation.2] Instance should disable support for embedding HTML JavaScript code created using the [code] tag",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not disable support for embedding HTML JavaScript code created using the [code] tag. Use the glide.ui.security.codetag.allow_script property to disable support for embedding HTML JavaScript code created using of the [code] tag. The Now Platform mitigates many injection and cross-site attacks by implementing escaping and encoding techniques. As a result, users can't write and submit HTML formatted inputs for journal fields. However, journal fields can render text enclosed within code tags as HTML. Input validation must occur in the application to defend against cross-site scripting attacks. These attacks enable foreign scripts to execute on the user session in the logged in browser's context. Attackers can use it to steal session information and sensitive data. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Allow JavaScript tags in embedded HTML (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/allow-javascript-tags-in-embedded-html.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.1] Instance should disable support for embedding HTML code created using the [code] tag",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does disable support for embedding HTML code created using the [code] tag.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Allow embedded HTML code (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/allow-embedded-html-code.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_check_unsanitized_html_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.3] Instance should enforce sanitization behavior of translated_html fields on a global level for field assignments
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "com.glide.security.check_unsanitized_html"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "enforce":
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
            "Title": "[Servicenow.InputValidation.3] Instance should enforce sanitization behavior of translated_html fields on a global level for field assignments",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not enforce sanitization behavior of translated_html fields on a global level for field assignments. Use the 'com.glide.security.check_unsanitized_html' property to enforce sanitization behavior of translated_html fields on a global level for field assignments. Input validation must occur on the application to defend against cross-site scripting attacks. These attacks enable foreign scripts to execute on user sessions in the logged in browser's context. Attackers can use it to steal session information and sensitive data. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Check Unsanitized Html (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/check-unsanitized-html.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.3] Instance should enforce sanitization behavior of translated_html fields on a global level for field assignments",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does enforce sanitization behavior of translated_html fields on a global level for field assignments.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Check Unsanitized Html (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/check-unsanitized-html.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_client_generated_scripts_sandbox_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.4] Instance should be configured to enable script sandboxing
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.script.use.sandbox"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Title": "[Servicenow.InputValidation.4] Instance should be configured to enable script sandboxing",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to enable script sandboxing. Use the glide.script.use.sandbox property to enable script sandboxing. The Now Platform provides wide variety of features and functionality through JavaScript queries. However, without appropriate authorization and validation, there is a potential for an attacker to perform unauthorized operations against the platform. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Client generated scripts sandbox (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/client-generated-scripts-sandbox.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.4] Instance should be configured to enable script sandboxing",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to enable script sandboxing.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Client generated scripts sandbox (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/client-generated-scripts-sandbox.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_enable_ajaxevaluate_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.5] Instance should disable AJAXEvaluate to restrict arbitrary client script execution
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.script.allow.ajaxevaluate"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Title": "[Servicenow.InputValidation.5] Instance should disable AJAXEvaluate to restrict arbitrary client script execution",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not disable AJAXEvaluate to restrict arbitrary client script execution. Use the glide.script.allow.ajaxevaluate property to restrict arbitrary client script execution using the system API on the server side. AJAXEvaluate can allow arbitrary JavaScript code to execute on the client browser by applying the server-side objects. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Enable AJAXEvaluate (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/enable-ajaxevaluate.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.5] Instance should disable AJAXEvaluate to restrict arbitrary client script execution",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does disable AJAXEvaluate to restrict arbitrary client script execution.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Enable AJAXEvaluate (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/enable-ajaxevaluate.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_escape_excel_formula_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.6] Instance should be configured to prevent Excel or formula injection
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.export.escape_formulas"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Title": "[Servicenow.InputValidation.6] Instance should be configured to prevent Excel or formula injection",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to prevent Excel or formula injection. Use the glide.export.escape_formulas property to prevent Excel Injection, also, known as formula injection. Excel injection occurs when websites embed untrusted entries inside Excel files. When you use a spreadsheet application such as Microsoft Excel, or LibreOffice Call, to open a file, any cells starting with +, -, =, or @ are interpreted as a formula. When you set the glide.export.escape_formulas property to true, string values starting with +, -, =, or @ are prepended with a single apostrophe when you export to CSV, XLS, or XLSX files. Malicious formulae pose a risk even when the embedding spreadsheet doesn't contain any sensitive information, as they can be used to compromise the viewer's computer. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Escape Excel formula (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/escape-excel-formula.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.6] Instance should be configured to prevent Excel or formula injection",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to prevent Excel or formula injection.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Escape Excel formula (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/escape-excel-formula.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_escape_html_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.7] Instance should be configured to escape HTML
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.escape_html_list_field"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Title": "[Servicenow.InputValidation.7] Instance should be configured to escape HTML",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to escape HTML. Use the glide.ui.escape_html_list_field property to force HTML escapes for HTML fields in a list view. HTML is one of the types that can be assigned to the dictionary fields. Assigning HTML fields to any field type provides the functionality to format content using HTML codes (for example, <p>, <a href>, <b>, <font>, <img>). A malicious user can inject HTML code within the form field to execute unwanted scripts on different client/user sessions. Input validation must occur on the application to defend against cross-site scripting attacks. These attacks enable foreign scripts to execute on user sessions in the logged in browser's context. Attackers can use it to steal session information and sensitive data. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Escape HTML (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/escape-html.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.7] Instance should be configured to escape HTML",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to escape HTML.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Escape HTML (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/escape-html.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_escape_javascript_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.8] Instance should be configured to escape JavaScript
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.html.escape_script"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Title": "[Servicenow.InputValidation.8] Instance should be configured to escape JavaScript",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to escape JavaScript. Use the glide.html.escape_script property to force escape from JavaScript (<script></script>) tags in HTML fields during list views. HTML is one of the types that can be assigned to the dictionary fields. Assigning HTML fields to any field type provides functionality to the user to format the content using HTML codes (for example, <p>, <a href>, <b>, <font>, <img>). If you set glide.html.escape_script to false, the (<script></script>) tags may appear when you select that column in a list view while viewing a table or record listing. Input validation must occur in the application to defend against cross-site scripting attacks. These attacks enable foreign scripts to execute on user session in the logged in browser's context. Attackers can use it to steal session information and sensitive data. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Escape JavaScript (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/escape-javascript.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.8] Instance should be configured to escape JavaScript",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to escape JavaScript.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Escape JavaScript (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/escape-javascript.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_escape_jelly_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.9] Instance should be configured to escape Jelly
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.escape_all_script"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Title": "[Servicenow.InputValidation.9] Instance should be configured to escape Jelly",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to escape Jelly. Use the glide.ui.escape_all_script property to force escape of all scripts injected into Jelly. It escapes all the JS and HTML strings included in <j:jelly> ... </j:jelly> before they are written to the output stream, preventing several XSS issues from occurring. Input validation has to occur on all the user input being entered on the application. By doing so, injection attacks against the platform can be defended and protected. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Escape Jelly (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/escape-jelly.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.9] Instance should be configured to escape Jelly",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to escape Jelly.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Escape Jelly (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/escape-jelly.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_escape_xml_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.10] Instance should be configured to escape XML
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.escape_text"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Title": "[Servicenow.InputValidation.10] Instance should be configured to escape XML",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to escape XML. Use the glide.ui.escape_text property to force escape of XML values at the parser level before transmitting them to the client's browser. Cross-site scripting occurs when an attacker injects malicious JavaScript into an entry point. The platform/application fails to escape the malicious JavaScript before transmitting it to the victim's browser for execution. Input validation must occur on the application to defend against cross-site scripting attacks. These attacks enable foreign scripts to execute on user session in the logged in browser's context. Attackers can use it to steal session information and sensitive data. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Escape XML (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/escape-xml.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.10] Instance should be configured to escape XML",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to escape XML.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Escape XML (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/escape-xml.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_html_sanitizer_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.11] Instance should be configured to sanitize HTML input
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.html.sanitize_all_fields"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Title": "[Servicenow.InputValidation.11] Instance should be configured to sanitize HTML input",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to sanitize HTML input. Use the glide.html.sanitize_all_fields property to enable the HTMLSanitizer script include, which sanitizes HTML input based on exclusion listed and inclusion listed attributes configured in a script. User input should be securely treated when the data is being stored and processed on the application.This reduces client-side cross-site scripting attacks by output encoding the data. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the HTML sanitizer (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/html-sanitizer.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.11] Instance should be configured to sanitize HTML input",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to sanitize HTML input.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the HTML sanitizer (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/html-sanitizer.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_javascript_jelly_interpolation_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.12] Instance should mitigate against malicious code execution attacks that can occur using Jelly Injection
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.ui.jelly.js_interpolation.protect"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
    # NOTE: This is where the check evaluation happens - in SNOW these may be Bools or Numbers but will come back as Strings
    # always evaluate a failing condition first which should be the OPPOSITE of the SNOW reccomendation as sometimes the values
    # are not a simple Boolean expression
    if propertyValue != "True":
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
            "Title": "[Servicenow.InputValidation.12] Instance should mitigate against malicious code execution attacks that can occur using Jelly Injection",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not mitigate against malicious code execution attacks that can occur using Jelly Injection. Use the 'glide.ui.jelly.js_interpolation.protect' property to ensure that any JavaScript about to be executed on a Jelly page is protected from injection with the help of Jelly interpolation. JEXL injection is a form of input injection unique to the Now Platform that can lead to both cross-site request forgery and code execution. Completely turning off the protection may potentially open many P1 security vulnerabilities. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Jelly/JS interpolation (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/jelly-js-interpolation.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.12] Instance should mitigate against malicious code execution attacks that can occur using Jelly Injection",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does mitigate against malicious code execution attacks that can occur using Jelly Injection.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Jelly/JS interpolation (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/jelly-js-interpolation.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

@registry.register_check("servicenow.inputvalidation")
def servicenow_sspm_soap_request_strict_security_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [Servicenow.InputValidation.13] Instance should ensure security ACLs are checked and validated even when the records are accessed through SOAP calls
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.soap.strict_security"
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
        assetB64 = None
    else:
        propertyValue = str(propFinder["value"])
        propDescription = str(propFinder["description"]).replace("\n    ", "")
        propId = str(propFinder["sys_id"])
        propCreatedOn = str(propFinder["sys_created_on"])
        propCreatedBy = str(propFinder["sys_created_by"])
        propUpdatedOn = str(propFinder["sys_updated_on"])
        propUpdatedBy = str(propFinder["sys_updated_by"])
        propScope = str(propFinder["sys_scope"]["value"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(propFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
            "Title": "[Servicenow.InputValidation.13] Instance should ensure security ACLs are checked and validated even when the records are accessed through SOAP calls",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not ensure security ACLs are checked and validated even when the records are accessed through SOAP calls. Use the 'glide.soap.strict_security' property to enforces web service security. Without appropriate authorization configured on the incoming SOAP requests, an unauthorized user can get access to sensitive content/data on the target instance. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the SOAP request strict security (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/soap-request-strict-security.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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
            "Title": "[Servicenow.InputValidation.13] Instance should ensure security ACLs are checked and validated even when the records are accessed through SOAP calls",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does ensure security ACLs are checked and validated even when the records are accessed through SOAP calls.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the SOAP request strict security (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/soap-request-strict-security.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "ServiceNow",
                "ProviderType": "SaaS",
                "ProviderAccountId": SNOW_INSTANCE_NAME,
                "AssetRegion": SNOW_INSTANCE_REGION,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "System Properties",
                "AssetComponent": "System Property"
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
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
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

# END ??