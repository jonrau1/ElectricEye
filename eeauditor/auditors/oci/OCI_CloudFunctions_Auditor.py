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

import os
import oci
from oci.config import validate_config
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def process_response(responseObject):
    """
    Receives an OCI Python SDK `Response` type (differs by service) and returns a JSON object
    """

    payload = json.loads(
        str(
            responseObject
        )
    )

    return payload

def get_cloud_function_apps(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_cloud_function_apps")
    if response:
        return response

    # Create & Validate OCI Creds - do this after cache check to avoid doing it a lot
    config = {
        "tenancy": ociTenancyId,
        "user": ociUserId,
        "region": ociRegionName,
        "fingerprint": ociUserApiKeyFingerprint,
        "key_file": os.environ["OCI_PEM_FILE_PATH"],
        
    }
    validate_config(config)

    funcMgmtClient = oci.functions.FunctionsManagementClient(config)

    aListOfAppsAndFunctions = []

    for compartment in ociCompartments:
        for app in process_response(funcMgmtClient.list_applications(compartment_id=compartment).data):
            # Create a new nested list in the application dict to hold the individual functions
            app["functions"] = []
            for function in process_response(
                funcMgmtClient.list_functions(application_id=app["id"]).data
            ):
                app["functions"].append(function)
            aListOfAppsAndFunctions.append(app)

    cache["get_cloud_function_apps"] = aListOfAppsAndFunctions
    return cache["get_cloud_function_apps"]

def get_scanned_repositories(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_scanned_repositories")
    if response:
        return response

    # Create & Validate OCI Creds - do this after cache check to avoid doing it a lot
    config = {
        "tenancy": ociTenancyId,
        "user": ociUserId,
        "region": ociRegionName,
        "fingerprint": ociUserApiKeyFingerprint,
        "key_file": os.environ["OCI_PEM_FILE_PATH"],
        
    }
    validate_config(config)

    artifactClient = oci.artifacts.ArtifactsClient(config)
    vssClient = oci.vulnerability_scanning.VulnerabilityScanningClient(config)

    scannedContainerRegistryRepos = []

    namespace = process_response(artifactClient.get_container_configuration(compartment_id=compartment).data)["namespace"]

    for compartment in ociCompartments:
        for targets in process_response(vssClient.list_container_scan_targets(compartment_id=compartment).data)["items"]:
            targetUrl = targets["target_registry"]["url"]
            for targetrepo in targets["target_registry"]["repositories"]:
                # The repo name on its own isn't referenced by Cloud Functions, only the full tag including the OCR url, namespace, etc
                # so we need to recreate that and compare it to the image split off by the version using .split(":")..
                # ...just look at how it's down in Check 5, it's great, I promise
                repoFqdn = f"{targetUrl}/{namespace}/{targetrepo}"
                if repoFqdn not in scannedContainerRegistryRepos:
                    scannedContainerRegistryRepos.append(repoFqdn)

    cache["get_scanned_repositories"] = scannedContainerRegistryRepos
    return cache["get_scanned_repositories"]

# Function Applications should have NSGs
@registry.register_check("oci.cloudfunctions")
def oci_cloud_functions_apps_use_nsgs_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.CloudFunctions.1] Oracle Cloud Functions applications should have at least one Network Security Group (NSG) assigned
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for application in get_cloud_function_apps(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(application,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = application["compartment_id"]
        applicationId = application["id"]
        applicationName = application["display_name"]
        lifecycleState = application["lifecycle_state"]
        createdAt = str(application["time_created"])

        if not application["network_security_group_ids"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-use-nsgs-chec",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-use-nsgs-chec",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.CloudFunctions.1] Oracle Cloud Functions applications should have at least one Network Security Group (NSG) assigned",
                "Description": f" Oracle Cloud Functions application {applicationName} in Compartment {compartmentId} in {ociRegionName} does not have a Network Security Group (NSG) assigned. Network security groups (NSGs) enable you to define ingress and egress rules that apply to particular VNICs and other resources in a VCN. Unlike a security list, which is attached to a subnet and which has security rules that apply to all the resources in that entire subnet, you can add individual resources to an NSG. Using NSGs rather than security lists gives you more granular control over the security rules that apply to individual resources. You can add an OCI Functions application to one or more NSGs (up to a maximum of five). Adding an application to an NSG enables you to define ingress and egress rules that apply to all the functions in that particular application. The ingress and egress rules defined for the NSG determine the access that the application's functions have to other network resources. Using NSGs is useful when you have specified the same subnet for multiple applications that have different access requirements. You can add the applications to different NSGs, enabling you to apply different security rules to the functions running in those applications. For example, you might want functions in one application to access a database and object storage, and functions in a second application to access the database and make an external call through a NAT gateway to a REST service on the public internet. Using NSGs enables you to have both applications in the same subnet without compromising network security. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on network security and using NSGs with Cloud Function Applications refer to the Adding Applications to Network Security Groups (NSGs) section of the Oracle Cloud Infrastructure Documentation for Functions.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsusingnsgs.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Oracle Cloud Functions",
                    "AssetComponent": "Application"
                },
                "Resources": [
                    {
                        "Type": "OciCloudFunctionsApplication",
                        "Id": applicationId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": applicationName,
                                "Id": applicationId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-use-nsgs-chec",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-use-nsgs-chec",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.CloudFunctions.1] Oracle Cloud Functions applications should have at least one Network Security Group (NSG) assigned",
                "Description": f" Oracle Cloud Functions application {applicationName} in Compartment {compartmentId} in {ociRegionName} does have a Network Security Group (NSG) assigned.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on network security and using NSGs with Cloud Function Applications refer to the Adding Applications to Network Security Groups (NSGs) section of the Oracle Cloud Infrastructure Documentation for Functions.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsusingnsgs.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Oracle Cloud Functions",
                    "AssetComponent": "Application"
                },
                "Resources": [
                    {
                        "Type": "OciCloudFunctionsApplication",
                        "Id": applicationId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": applicationName,
                                "Id": applicationId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

# [OCI.CloudFunctions.2] Oracle Cloud Functions applications should enforce the usage of signed images from Oracle Container Registry
# composite True checks via application["image_policy_config"]["is_policy_enabled"] is False unless application["image_policy_config"] is None
# Signing Function Images and Enforcing the Use of Signed Images from Registry - https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsenforcingsignedimagesfromocir.htm

# [OCI.CloudFunctions.3] Oracle Cloud Functions applications should use more than one subnet to promote high availability
# if len(application["subnet_ids"]) == 0:
# Creating an Application - https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionscreatingapps-task.htm#functionscreatingapps-taskcopy

# [OCI.CloudFunctions.4] Oracle Cloud Functions applications should consider using tracing for Performance Monitoring
# if application["trace_config"]["is_enabled"] is False:
# Distributed Tracing for Functions - https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionstracing.htm

# [OCI.CloudFunctions.5] Oracle Cloud Functions should only use images that are scanned for vulnerabilities
# for function in application["functions"] - and call the helper too
# Scanning Function Images for Vulnerabilities - https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsimagescanning.htm

## END ??