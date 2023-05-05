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

@registry.register_check("servicenow.securecommunications")
def servicenow_sspm_certificate_trust_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SecureCommunications.1] Instance should be configured to enforce certificate validation for outgoing requests
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "com.glide.communications.trustmanager_trust_all"
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
            "Title": "[SSPM.Servicenow.SecureCommunications.1] Instance should be configured to enforce certificate validation for outgoing requests",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to enforce certificate validation for outgoing requests. By default, the 'com.glide.communications.trustmanager_trust_all' property is set to false. The Now Platform only trusts certificates that it can verify against the JVM certificate store. Self-signed and enterprise-signed certificates are not trusted. For confidentiality and integrity reasons, application should validate the certificate's CA before using the certificate for any transactional operations. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Certificate trust (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/certificate-trust.html",
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
                    "NIST CSF V1.1 PR.DS-2",
                    "NIST SP 800-53 Rev. 4 SC-8",
                    "NIST SP 800-53 Rev. 4 SC-11",
                    "NIST SP 800-53 Rev. 4 SC-12",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.13.2.1",
                    "ISO 27001:2013 A.13.2.3",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3"
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
             "Title": "[SSPM.Servicenow.SecureCommunications.1] Instance should be configured to enforce certificate validation for outgoing requests",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to enforce certificate validation for outgoing requests.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Certificate trust (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/certificate-trust.html",
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
                    "NIST CSF V1.1 PR.DS-2",
                    "NIST SP 800-53 Rev. 4 SC-8",
                    "NIST SP 800-53 Rev. 4 SC-11",
                    "NIST SP 800-53 Rev. 4 SC-12",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.13.2.1",
                    "ISO 27001:2013 A.13.2.3",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.securecommunications")
def servicenow_sspm_disable_ssl_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SecureCommunications.2] Instance should be configured to disable SSLv2 and SSLv3 outbound connections
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "glide.outbound.sslv3.disabled"
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
            "Title": "[SSPM.Servicenow.SecureCommunications.2] Instance should be configured to disable SSLv2 and SSLv3 outbound connections",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to disable SSLv2 and SSLv3 outbound connections. Use the glide.outbound.sslv3.disabled property to force the MID Server to use TLS when making outbound connections, such as REST and SOAP requests. Normally, outbound connections from an instance are forced to use TLS instead of SSL. Legacy versions of SSL were proven to be insecure when utilized for HTTP secure shell implementation, due to client-side attacks, including BEAST and SSL heart-bleed. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Disabling SSLv2/SSLv3 (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/disabling-sslv2-sslv3.html",
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
                    "NIST CSF V1.1 PR.DS-2",
                    "NIST SP 800-53 Rev. 4 SC-8",
                    "NIST SP 800-53 Rev. 4 SC-11",
                    "NIST SP 800-53 Rev. 4 SC-12",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.13.2.1",
                    "ISO 27001:2013 A.13.2.3",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3"
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
            "Title": "[SSPM.Servicenow.SecureCommunications.2] Instance should be configured to disable SSLv2 and SSLv3 outbound connections",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to disable SSLv2 and SSLv3 outbound connections.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Disabling SSLv2/SSLv3 (instance security hardening) section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/disabling-sslv2-sslv3.html",
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
                    "NIST CSF V1.1 PR.DS-2",
                    "NIST SP 800-53 Rev. 4 SC-8",
                    "NIST SP 800-53 Rev. 4 SC-11",
                    "NIST SP 800-53 Rev. 4 SC-12",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.13.2.1",
                    "ISO 27001:2013 A.13.2.3",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.securecommunications")
def servicenow_sspm_http_client_hostname_verification_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SecureCommunications.3] Instance should be configured to verify hostname and certificate chain presented by remote SSL hosts
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "com.glide.communications.httpclient.verify_hostname"
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
            "Title": "[SSPM.Servicenow.SecureCommunications.3] Instance should be configured to verify hostname and certificate chain presented by remote SSL hosts",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to verify hostname and certificate chain presented by remote SSL hosts. Set 'com.glide.communications.httpclient.verify_hostname' to true to protect against MitM (man-in-the-middle) attacks in which communications between two parties are intercepted. Setting this property overrides the com.glide.communications.trustmanager_trust_all property. Allows or prevents the http client to connect to a potentially harmful hostname without exception. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the HTTP client hostname verification section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/http-client-verify-hostname.html",
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
                    "NIST CSF V1.1 PR.DS-2",
                    "NIST SP 800-53 Rev. 4 SC-8",
                    "NIST SP 800-53 Rev. 4 SC-11",
                    "NIST SP 800-53 Rev. 4 SC-12",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.13.2.1",
                    "ISO 27001:2013 A.13.2.3",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3"
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
            "Title": "[SSPM.Servicenow.SecureCommunications.3] Instance should be configured to verify hostname and certificate chain presented by remote SSL hosts",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to verify hostname and certificate chain presented by remote SSL hosts.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the HTTP client hostname verification section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/http-client-verify-hostname.html",
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
                    "NIST CSF V1.1 PR.DS-2",
                    "NIST SP 800-53 Rev. 4 SC-8",
                    "NIST SP 800-53 Rev. 4 SC-11",
                    "NIST SP 800-53 Rev. 4 SC-12",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.13.2.1",
                    "ISO 27001:2013 A.13.2.3",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("servicenow.securecommunications")
def servicenow_sspm_revoked_certificate_revocation_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.SecureCommunications.4] Instance should be configured to verify the revocation of all certificates
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Name of the property to evaluate against
    evalTarget = "com.glide.communications.httpclient.verify_revoked_certificate"
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
            "Title": "[SSPM.Servicenow.SecureCommunications.4] Instance should be configured to verify the revocation of all certificates",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is not configured to verify the revocation of all certificates. Use this property to disable the certification verification process that evaluates all certifications in the certification chain by checking the revocation status. API calls that use the high-security plugin may want to configure this property. If the full certification chain is not defined in the instance trust store or the certificates used may not be compatible with an OCSP (Online Certificate Status Protocol) revocation check, errors may be returned to the API calls. API calls using the High Security plugin will not be verified using an OCSP revocation check in the instance trust store. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Revoked certificate verification section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/verify-revoked-certificate.htmll",
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
                    "NIST CSF V1.1 PR.DS-2",
                    "NIST SP 800-53 Rev. 4 SC-8",
                    "NIST SP 800-53 Rev. 4 SC-11",
                    "NIST SP 800-53 Rev. 4 SC-12",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.13.2.1",
                    "ISO 27001:2013 A.13.2.3",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3"
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
            "Title": "[SSPM.Servicenow.SecureCommunications.4] Instance should be configured to verify the revocation of all certificates",
            "Description": f"Servicenow instance {SNOW_INSTANCE_NAME} is configured to verify the revocation of all certificates.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information refer to the Revoked certificate verification section of the Servicenow Product Documentation.",
                    "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/verify-revoked-certificate.htmll",
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
                    "NIST CSF V1.1 PR.DS-2",
                    "NIST SP 800-53 Rev. 4 SC-8",
                    "NIST SP 800-53 Rev. 4 SC-11",
                    "NIST SP 800-53 Rev. 4 SC-12",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                    "ISO 27001:2013 A.13.1.1",
                    "ISO 27001:2013 A.13.2.1",
                    "ISO 27001:2013 A.13.2.3",
                    "ISO 27001:2013 A.14.1.2",
                    "ISO 27001:2013 A.14.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

# END ??