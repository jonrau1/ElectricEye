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

def get_servicenow_plugins(cache: dict):
    """
    Pulls the entire "v_plugin" table which are the raw installed Plugins
    """
    response = cache.get("get_servicenow_plugins")
    if response:
        print("servicenow.access_control cache hit!")
        return response
    
    # Will need to create the pysnow.Client object everywhere - doesn't appear to be thread-safe
    snow = pysnow.Client(
        instance=SNOW_INSTANCE_NAME,
        user=SNOW_SSPM_USERNAME,
        password=SNOW_SSPM_PASSWORD
    )

    pluginResource = snow.resource(api_path='/table/v_plugin')
    plugins = pluginResource.get().all()

    cache["get_servicenow_plugins"] = plugins

    return cache["get_servicenow_plugins"]

# NOTE: Dict search next() iterator thingy from: https://stackoverflow.com/questions/8653516/search-a-list-of-dictionaries-in-python

@registry.register_check("servicenow.securityplugins")
def servicenow_sspm_contextual_security_role_mgmt_plugin_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SecurityPlugins.1] Instance should have the Contextual Security: Role Management (V2) plugin installed and activated
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    pluginId = "com.glide.role_management"
    # Get cached plugins
    pluginsCache = get_servicenow_plugins(cache)

    # There should not ever be a duplicate plugin, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    pluginFinder = next((plugin for plugin in pluginsCache if plugin["sys_id"] == pluginId), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if pluginFinder == False:
        pluginActivityStatus = "inactive"
        pluginState = "uninstalled"
        pluginName = "Contextual Security: Role Management V2"
        pluginVersion = ""
        pluginDefinition = ""
        pluginCreatedOn = ""
        pluginCreatedBy = ""
        pluginUpdatedOn = ""
        pluginUpdatedBy = ""
        pluginLicenseModel = ""
        pluginScope = ""
        assetB64 = None
    else:
        pluginActivityStatus = str(pluginFinder["active"])
        pluginState = str(pluginFinder["state"])
        pluginName = str(pluginFinder["name"])
        pluginVersion = str(pluginFinder["available_version"])
        pluginDefinition = str(pluginFinder["definition"]).replace("\n    ", "").replace("\n      ", "")
        pluginCreatedOn = str(pluginFinder["sys_created_on"])
        pluginCreatedBy = str(pluginFinder["sys_created_by"])
        pluginUpdatedOn = str(pluginFinder["sys_updated_on"])
        pluginUpdatedBy = str(pluginFinder["sys_updated_by"])
        pluginLicenseModel = str(pluginFinder["license_model"])
        pluginScope = str(pluginFinder["scope"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(pluginFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)   
    # NOTE: This is where the check evaluation happens - for Plugins if they are not present at all they will not show up in the v_plugin table
    # so we need to set some fake "uninstalled" values for the state and manually set the activity status to "inative" - obviously this would not
    # appear if the plugin wasn't there...so the logic checks it is "published" (default value for installed) and that it is "active" as well
    if (pluginActivityStatus != "active" and pluginState != "published"):
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.1] Instance should have the Contextual Security: Role Management (V2) plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not have the Contextual Security: Role Management (V2) plugin installed and activated. Activate the Contextual Security: Role Management (com.glide.role_management) plugin to enable contextual security, which secures a record/information using create, read, write, and delete functionality. Functional level access controls must be enforced from the server side prior to executing CRUD operations, ensuring the appropriate level of access to instance users. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Contextual Security: Role Management plugin (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/contextual-security.html",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.1] Instance should have the Contextual Security: Role Management (V2) plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does have the Contextual Security: Role Management (V2) plugin installed and activated.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Contextual Security: Role Management plugin (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/contextual-security.html",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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

@registry.register_check("servicenow.securityplugins")
def servicenow_sspm_explicit_role_plugin_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SecurityPlugins.2] Instance should have the Explicit Role plugin installed and activated
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    pluginId = "com.glide.explicit_roles"
    # Get cached plugins
    pluginsCache = get_servicenow_plugins(cache)

    # There should not ever be a duplicate plugin, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    pluginFinder = next((plugin for plugin in pluginsCache if plugin["sys_id"] == pluginId), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if pluginFinder == False:
        pluginActivityStatus = "inactive"
        pluginState = "uninstalled"
        pluginName = "Explicit Role"
        pluginVersion = ""
        pluginDefinition = ""
        pluginCreatedOn = ""
        pluginCreatedBy = ""
        pluginUpdatedOn = ""
        pluginUpdatedBy = ""
        pluginLicenseModel = ""
        pluginScope = ""
        assetB64 = None
    else:
        pluginActivityStatus = str(pluginFinder["active"])
        pluginState = str(pluginFinder["state"])
        pluginName = str(pluginFinder["name"])
        pluginVersion = str(pluginFinder["available_version"])
        pluginDefinition = str(pluginFinder["definition"]).replace("\n    ", "").replace("\n      ", "")
        pluginCreatedOn = str(pluginFinder["sys_created_on"])
        pluginCreatedBy = str(pluginFinder["sys_created_by"])
        pluginUpdatedOn = str(pluginFinder["sys_updated_on"])
        pluginUpdatedBy = str(pluginFinder["sys_updated_by"])
        pluginLicenseModel = str(pluginFinder["license_model"])
        pluginScope = str(pluginFinder["scope"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(pluginFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)           
    # NOTE: This is where the check evaluation happens - for Plugins if they are not present at all they will not show up in the v_plugin table
    # so we need to set some fake "uninstalled" values for the state and manually set the activity status to "inative" - obviously this would not
    # appear if the plugin wasn't there...so the logic checks it is "published" (default value for installed) and that it is "active" as well
    if (pluginActivityStatus != "active" and pluginState != "published"):
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.2] Instance should have the Explicit Role plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not have the Explicit Role plugin installed and activated. Activate the Explicit Role (com.glide.explicit_roles) plugin to provide the instance with the new snc_internal and snc_external roles for B2B and B2C applications, preventing external users from accessing internal data. Enterprise users (employees) must have the internal role while non-enterprise users (non-employees) must have the external role. External Users (Non-employees) can access to many sensitive tables in the Now Platform that do not have any roles assigned to it. They are meant to be accessible by internal users (Employees) only. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Explicit Role plugin (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/explicit-role-plugin.htmll",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.2] Instance should have the Explicit Role plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does have the Explicit Role plugin installed and activated.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Explicit Role plugin (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/explicit-role-plugin.htmll",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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

@registry.register_check("servicenow.securityplugins")
def servicenow_sspm_saml20_web_browser_sso_profile_plugin_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SecurityPlugins.3] Instance should have the SAML 2.0 Single Sign-On plugin installed and activated
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    pluginId = "com.snc.integration.sso.saml20.update1"
    # Get cached plugins
    pluginsCache = get_servicenow_plugins(cache)

    # There should not ever be a duplicate plugin, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    pluginFinder = next((plugin for plugin in pluginsCache if plugin["sys_id"] == pluginId), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if pluginFinder == False:
        pluginActivityStatus = "inactive"
        pluginState = "uninstalled"
        pluginName = "SAML 2.0 Single Sign-On"
        pluginVersion = ""
        pluginDefinition = ""
        pluginCreatedOn = ""
        pluginCreatedBy = ""
        pluginUpdatedOn = ""
        pluginUpdatedBy = ""
        pluginLicenseModel = ""
        pluginScope = ""
        assetB64 = None
    else:
        pluginActivityStatus = str(pluginFinder["active"])
        pluginState = str(pluginFinder["state"])
        pluginName = str(pluginFinder["name"])
        pluginVersion = str(pluginFinder["available_version"])
        pluginDefinition = str(pluginFinder["definition"]).replace("\n    ", "").replace("\n      ", "")
        pluginCreatedOn = str(pluginFinder["sys_created_on"])
        pluginCreatedBy = str(pluginFinder["sys_created_by"])
        pluginUpdatedOn = str(pluginFinder["sys_updated_on"])
        pluginUpdatedBy = str(pluginFinder["sys_updated_by"])
        pluginLicenseModel = str(pluginFinder["license_model"])
        pluginScope = str(pluginFinder["scope"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(pluginFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)           
    # NOTE: This is where the check evaluation happens - for Plugins if they are not present at all they will not show up in the v_plugin table
    # so we need to set some fake "uninstalled" values for the state and manually set the activity status to "inative" - obviously this would not
    # appear if the plugin wasn't there...so the logic checks it is "published" (default value for installed) and that it is "active" as well
    if (pluginActivityStatus != "active" and pluginState != "published"):
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.3] Instance should have the SAML 2.0 Single Sign-On plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not have the SAML 2.0 Single Sign-On plugin installed and activated. The com.snc.integration.sso.saml20.update1 plugin ensures that the status of the SAML 2.0 Single Sign-On plugin is active. Security Assertion Markup Language (SAML) is an XML-based standard for exchanging authentication and authorization data between security domains. SAML exchanges security information between an identity provider (a producer of assertions) and a Service Provider (a consumer of assertions). The sso.multi.installer installs all required SAML-related plugins, and also contains saml2 implementation scripts that provide options for response validation. To learn more, see the topics in References in More Information. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the SAML 2.0 web browser SSO profile (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/saml-20-web-browser-sso-profile.html",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.3] Instance should have the SAML 2.0 Single Sign-On plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does have the SAML 2.0 Single Sign-On plugin installed and activated.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the SAML 2.0 web browser SSO profile (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/saml-20-web-browser-sso-profile.html",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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

@registry.register_check("servicenow.securityplugins")
def servicenow_sspm_security_jumpstart_plugin_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SecurityPlugins.4] Instance should have the Security Jump Start (ACL Rules) plugin installed and activated
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    pluginId = "com.snc.system_security"
    # Get cached plugins
    pluginsCache = get_servicenow_plugins(cache)

    # There should not ever be a duplicate plugin, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    pluginFinder = next((plugin for plugin in pluginsCache if plugin["sys_id"] == pluginId), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if pluginFinder == False:
        pluginActivityStatus = "inactive"
        pluginState = "uninstalled"
        pluginName = "Security Jump Start (ACL Rules)"
        pluginVersion = ""
        pluginDefinition = ""
        pluginCreatedOn = ""
        pluginCreatedBy = ""
        pluginUpdatedOn = ""
        pluginUpdatedBy = ""
        pluginLicenseModel = ""
        pluginScope = ""
        assetB64 = None
    else:
        pluginActivityStatus = str(pluginFinder["active"])
        pluginState = str(pluginFinder["state"])
        pluginName = str(pluginFinder["name"])
        pluginVersion = str(pluginFinder["available_version"])
        pluginDefinition = str(pluginFinder["definition"]).replace("\n    ", "").replace("\n      ", "")
        pluginCreatedOn = str(pluginFinder["sys_created_on"])
        pluginCreatedBy = str(pluginFinder["sys_created_by"])
        pluginUpdatedOn = str(pluginFinder["sys_updated_on"])
        pluginUpdatedBy = str(pluginFinder["sys_updated_by"])
        pluginLicenseModel = str(pluginFinder["license_model"])
        pluginScope = str(pluginFinder["scope"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(pluginFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)           
    # NOTE: This is where the check evaluation happens - for Plugins if they are not present at all they will not show up in the v_plugin table
    # so we need to set some fake "uninstalled" values for the state and manually set the activity status to "inative" - obviously this would not
    # appear if the plugin wasn't there...so the logic checks it is "published" (default value for installed) and that it is "active" as well
    if (pluginActivityStatus != "active" and pluginState != "published"):
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.4] Instance should have the Security Jump Start (ACL Rules) plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not have the Security Jump Start (ACL Rules) plugin installed and activated. Activate the Security Jump Start (ACL Rules) (com.snc.system_security) plugin to create several important ACLs that validate the Access Controls on some of the key system tables within the Now Platform. These rules provide a jump-start on securing many system tables, making it easier for an organization to get an instance into production. The Security Jump Start (ACL Rules) plugin is installed automatically on all new instances. Access control should be enforced to lock down the unintended access to the instance. ACL jumpstart rules were created to provide a starting point on securing many system tables to make it easier for an organization to quickly get into production. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Security jump start (ACL rules) (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/security-jump-start-acl-rules.html",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.4] Instance should have the Security Jump Start (ACL Rules) plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does have the Security Jump Start (ACL Rules) plugin installed and activated.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Security jump start (ACL rules) (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/security-jump-start-acl-rules.html",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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

@registry.register_check("servicenow.securityplugins")
def servicenow_sspm_snc_access_control_plugin_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SecurityPlugins.5] Instance should have the SNC Access Control plugin installed and activated
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    pluginId = "com.snc.snc_access_control"
    # Get cached plugins
    pluginsCache = get_servicenow_plugins(cache)

    # There should not ever be a duplicate plugin, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    pluginFinder = next((plugin for plugin in pluginsCache if plugin["sys_id"] == pluginId), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if pluginFinder == False:
        pluginActivityStatus = "inactive"
        pluginState = "uninstalled"
        pluginName = "SNC Access Control"
        pluginVersion = ""
        pluginDefinition = ""
        pluginCreatedOn = ""
        pluginCreatedBy = ""
        pluginUpdatedOn = ""
        pluginUpdatedBy = ""
        pluginLicenseModel = ""
        pluginScope = ""
        assetB64 = None
    else:
        pluginActivityStatus = str(pluginFinder["active"])
        pluginState = str(pluginFinder["state"])
        pluginName = str(pluginFinder["name"])
        pluginVersion = str(pluginFinder["available_version"])
        pluginDefinition = str(pluginFinder["definition"]).replace("\n    ", "").replace("\n      ", "")
        pluginCreatedOn = str(pluginFinder["sys_created_on"])
        pluginCreatedBy = str(pluginFinder["sys_created_by"])
        pluginUpdatedOn = str(pluginFinder["sys_updated_on"])
        pluginUpdatedBy = str(pluginFinder["sys_updated_by"])
        pluginLicenseModel = str(pluginFinder["license_model"])
        pluginScope = str(pluginFinder["scope"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(pluginFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)           
    # NOTE: This is where the check evaluation happens - for Plugins if they are not present at all they will not show up in the v_plugin table
    # so we need to set some fake "uninstalled" values for the state and manually set the activity status to "inative" - obviously this would not
    # appear if the plugin wasn't there...so the logic checks it is "published" (default value for installed) and that it is "active" as well
    if (pluginActivityStatus != "active" and pluginState != "published"):
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.5] Instance should have the SNC Access Control plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not have the SNC Access Control plugin installed and activated. Activate the SNC Access Control (com.snc.snc_access_control) plugin to control access to your instances by Customer Service and Support personnel. The default configuration for the Now Platform enables Customer Service and Support to access instances through an internal process that creates short-term support credentials. Although all access is audited, some customers prefer to control this access. Without this Plugin, you can add unnecessary exposure of instance access to wider group of people. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the SNC Access Control plugin (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/snc-access-control-plugin.html",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.5] Instance should have the SNC Access Control plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does have the SNC Access Control plugin installed and activated.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the SNC Access Control plugin (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/snc-access-control-plugin.html",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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

@registry.register_check("servicenow.securityplugins")
def servicenow_sspm_email_spam_scoring_filtering_plugin_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SecurityPlugins.6] Instance should have the Email Filters plugin installed and activated
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    pluginId = "com.glide.email_filter"
    # Get cached plugins
    pluginsCache = get_servicenow_plugins(cache)

    # There should not ever be a duplicate plugin, use next() and a list comprehension to check if the
    # property we're evaluating is in the list of properties we get from the cache. If it is NOT then set the
    # value as `False` and we can fill in fake values. Not having a property for security hardening is the same
    # as a failed finding with a lot less fan fair
    pluginFinder = next((plugin for plugin in pluginsCache if plugin["sys_id"] == pluginId), False)
    # If we cannot find the property set "NOT_CONFIGURED" which will fail whatever the value should be
    if pluginFinder == False:
        pluginActivityStatus = "inactive"
        pluginState = "uninstalled"
        pluginName = "Email Filters"
        pluginVersion = ""
        pluginDefinition = ""
        pluginCreatedOn = ""
        pluginCreatedBy = ""
        pluginUpdatedOn = ""
        pluginUpdatedBy = ""
        pluginLicenseModel = ""
        pluginScope = ""
        assetB64 = None
    else:
        pluginActivityStatus = str(pluginFinder["active"])
        pluginState = str(pluginFinder["state"])
        pluginName = str(pluginFinder["name"])
        pluginVersion = str(pluginFinder["available_version"])
        pluginDefinition = str(pluginFinder["definition"]).replace("\n    ", "").replace("\n      ", "")
        pluginCreatedOn = str(pluginFinder["sys_created_on"])
        pluginCreatedBy = str(pluginFinder["sys_created_by"])
        pluginUpdatedOn = str(pluginFinder["sys_updated_on"])
        pluginUpdatedBy = str(pluginFinder["sys_updated_by"])
        pluginLicenseModel = str(pluginFinder["license_model"])
        pluginScope = str(pluginFinder["scope"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(pluginFinder,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)           
    # NOTE: This is where the check evaluation happens - for Plugins if they are not present at all they will not show up in the v_plugin table
    # so we need to set some fake "uninstalled" values for the state and manually set the activity status to "inative" - obviously this would not
    # appear if the plugin wasn't there...so the logic checks it is "published" (default value for installed) and that it is "active" as well
    if (pluginActivityStatus != "active" and pluginState != "published"):
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.6] Instance should have the Email Filters plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not have the Email Filters plugin installed and activated. Install the Email Filter (com.glide.email_filter) plugin to install email filtering within the instance. This filtering identifies existing headers, which enables you to decide what to do with the email based on the associated header. Every message sent through Now Platform email servers is assessed for the likelihood of being spam. Email filters enable administrators to use a condition builder or conditional script to specify when to ignore malicious incoming emails from known/unknown sender. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Email spam scoring and filtering (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/email-spam-scoring-and-filtering.html",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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
            "Id": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}/check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SSPM.Servicenow.SecurityPlugins.6] Instance should have the Email Filters plugin installed and activated",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does have the Email Filters plugin installed and activated.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Email spam scoring and filtering (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/email-spam-scoring-and-filtering.html",
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
                "AssetService": "System Plugins",
                "AssetComponent": "Plugin"
            },
            "Resources": [
                {
                    "Type": "ServicenowPlugin",
                    "Id": f"{SNOW_INSTANCE_NAME}/v_plugin/{pluginId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "ServicenowInstance": SNOW_INSTANCE_NAME,
                            "SysId": pluginId,
                            "PluginActivityStatus": pluginId,
                            "State": pluginActivityStatus,
                            "Name": pluginName,
                            "Version": pluginVersion,
                            "Definition": pluginDefinition,
                            "CreatedOn": pluginCreatedOn,
                            "CreatedBy": pluginCreatedBy,
                            "UpdatedOn": pluginUpdatedOn,
                            "UpdatedBy": pluginUpdatedBy,
                            "LicenseModel": pluginLicenseModel,
                            "Scope": pluginScope
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