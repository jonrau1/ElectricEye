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

    for compartment in ociCompartments:
        namespace = process_response(artifactClient.get_container_configuration(compartment_id=compartment).data)["namespace"]
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-use-nsgs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-use-nsgs-check",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-use-nsgs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-use-nsgs-check",
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

@registry.register_check("oci.cloudfunctions")
def oci_cloud_functions_apps_enforce_signed_images_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.CloudFunctions.2] Oracle Cloud Functions applications should enforce the usage of signed images from Oracle Container Registry
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

        # Evaluate 3 possible conditions of signing
        if application["image_policy_config"] is None:
            imageSigning = False
        else:
            if application["image_policy_config"]["is_policy_enabled"] is False:
                imageSigning = False
            else:
                imageSigning = True

        if imageSigning is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-enforce-signed-images-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-enforce-signed-images-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.CloudFunctions.2] Oracle Cloud Functions applications should enforce the usage of signed images from Oracle Container Registry",
                "Description": f" Oracle Cloud Functions application {applicationName} in Compartment {compartmentId} in {ociRegionName} does not enforce the usage of signed images from Oracle Container Registry. For compliance and security reasons, system administrators often want to deploy software into a production system only when they are satisfied that: comes from a trusted source and has not been modified since it was published, compromising its integrity. To meet these requirements, you can sign images stored in Oracle Cloud Infrastructure Registry. Signed images provide a way to verify both the source of an image and its integrity. Oracle Cloud Infrastructure Registry enables users or systems to push images to the registry and then sign them creating an image signature. To further enhance security, you can configure OCI Functions applications to only allow the creation, updating, deployment, and invocation of functions based on images in Oracle Cloud Infrastructure Registry that have been signed by particular master encryption keys. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on signing images and enforcing their usage with Cloud Function Applications refer to the Signing Function Images and Enforcing the Use of Signed Images from Registry section of the Oracle Cloud Infrastructure Documentation for Functions.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsenforcingsignedimagesfromocir.htm"
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
                        "NIST CSF V1.1 ID.SC-2",
                        "NIST CSF V1.1 PR.DS-6",
                        "NIST SP 800-53 Rev. 4 RA-2",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 PM-9",
                        "NIST SP 800-53 Rev. 4 SA-12",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SA-15",
                        "NIST SP 800-53 Rev. 4 SI-7",
                        "AICPA TSC CC7.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.2.1", 
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.15.2.2"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-enforce-signed-images-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-enforce-signed-images-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.CloudFunctions.2] Oracle Cloud Functions applications should enforce the usage of signed images from Oracle Container Registry",
                "Description": f" Oracle Cloud Functions application {applicationName} in Compartment {compartmentId} in {ociRegionName} does enforce the usage of signed images from Oracle Container Registry.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on signing images and enforcing their usage with Cloud Function Applications refer to the Signing Function Images and Enforcing the Use of Signed Images from Registry section of the Oracle Cloud Infrastructure Documentation for Functions.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsenforcingsignedimagesfromocir.htm"
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
                        "NIST CSF V1.1 ID.SC-2",
                        "NIST CSF V1.1 PR.DS-6",
                        "NIST SP 800-53 Rev. 4 RA-2",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 PM-9",
                        "NIST SP 800-53 Rev. 4 SA-12",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SA-15",
                        "NIST SP 800-53 Rev. 4 SI-7",
                        "AICPA TSC CC7.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.2.1", 
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.15.2.2"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.cloudfunctions")
def oci_cloud_functions_apps_subnet_high_availability_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.CloudFunctions.3] Oracle Cloud Functions applications should use more than one subnet to promote high availability
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

        if len(application["subnet_ids"]) == 1:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-subnet-high-availability-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-subnet-high-availability-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.CloudFunctions.3] Oracle Cloud Functions applications should use more than one subnet to promote high availability",
                "Description": f" Oracle Cloud Functions application {applicationName} in Compartment {compartmentId} in {ociRegionName} does not use more than one subnet to promote high availability. If a regional subnet has been defined, best practice is to select that subnet to make failover across availability domains simpler to implement. If a regional subnet has not been defined and you need to meet high availability requirements, select multiple subnets. Oracle recommends that the subnets are in the same region as the Docker registry that is used for the actual Functions within the Application. Additionally, note that a public subnet requires an internet gateway in the VCN, and a private subnet requires a service gateway in the VCN. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up subnets for Cloud Function Applications refer to the Creating an Application section of the Oracle Cloud Infrastructure Documentation for Functions.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionscreatingapps-task.htm#functionscreatingapps-taskcopy"
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-subnet-high-availability-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-subnet-high-availability-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.CloudFunctions.3] Oracle Cloud Functions applications should use more than one subnet to promote high availability",
                "Description": f" Oracle Cloud Functions application {applicationName} in Compartment {compartmentId} in {ociRegionName} does use more than one subnet to promote high availability.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up subnets for Cloud Function Applications refer to the Creating an Application section of the Oracle Cloud Infrastructure Documentation for Functions.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionscreatingapps-task.htm#functionscreatingapps-taskcopy"
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

@registry.register_check("oci.cloudfunctions")
def oci_cloud_functions_apps_active_tracing_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.CloudFunctions.4] Oracle Cloud Functions applications should consider using tracing for Performance Monitoring
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

        if application["trace_config"]["is_enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-active-tracing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-active-tracing-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.CloudFunctions.4] Oracle Cloud Functions applications should consider using tracing for Performance Monitoring",
                "Description": f" Oracle Cloud Functions application {applicationName} in Compartment {compartmentId} in {ociRegionName} does not use tracing for Performance Monitoring. When a function is invoked but doesn't run or perform as expected, you need to investigate the issue at a detailed level. The distributed tracing feature observes the function's execution as it moves through the different components of the system. You can trace and instrument standalone functions to debug execution and performance issues. You can also use function tracing to debug issues with complete serverless applications comprising multiple functions and services. The OCI Functions tracing capabilities are provided by the Oracle Cloud Infrastructure Application Performance Monitoring service. Features in Application Performance Monitoring (APM) enable you to identify and troubleshoot failures and latency issues in the functions you create and deploy. The Application Performance Monitoring Trace Explorer enables you to visualize the entire request flow and explore trace and span details for diagnostics. You can view and monitor slow traces and traces with errors. To isolate and identify trace issues, you can drill down into specific spans, such as page loads, AJAX calls, and service requests. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up tracing for Cloud Function Applications refer to the Distributed Tracing for Functions section of the Oracle Cloud Infrastructure Documentation for Functions.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionstracing.htm"
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
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-active-tracing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{applicationId}/oci-cloud-functions-apps-active-tracing-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.CloudFunctions.4] Oracle Cloud Functions applications should consider using tracing for Performance Monitoring",
                "Description": f" Oracle Cloud Functions application {applicationName} in Compartment {compartmentId} in {ociRegionName} does use tracing for Performance Monitoring.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up tracing for Cloud Function Applications refer to the Distributed Tracing for Functions section of the Oracle Cloud Infrastructure Documentation for Functions.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionstracing.htm"
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
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.cloudfunctions")
def oci_cloud_functions_image_vuln_scanned_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.CloudFunctions.5] Oracle Cloud Functions should only use images that are scanned for vulnerabilities
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Grab the scanned repos
    scannedRepositories = get_scanned_repositories(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint)

    for application in get_cloud_function_apps(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        if not application["functions"]:
            continue
        
        compartmentId = application["compartment_id"]
        # Run through the actual functions
        for function in application["functions"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(function,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            appId = function["application_id"]
            funcName = function["display_name"]
            funcId = function["id"]
            funcImage = function["image"]
            funcCreatedAt = str(function["time_created"])
            lifecycleState = function["lifecycle_state"]

            # Split off the version
            functionImageSourceRepo = funcImage.split(":")[0]

            if functionImageSourceRepo not in scannedRepositories:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{funcId}/oci-cloud-functions-use-scanned-images-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{funcId}/oci-cloud-functions-use-scanned-images-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[OCI.CloudFunctions.5] Oracle Cloud Functions should only use images that are scanned for vulnerabilities",
                    "Description": f" Oracle Cloud Function {funcName} in Compartment {compartmentId} in {ociRegionName} does not use an image that is scanned for vulnerabilities. In OCI Functions, a function's definition specifies the Docker image to push to, and pull from, a repository in Oracle Cloud Infrastructure Registry. You can set up Oracle Cloud Infrastructure Registry (also known as Container Registry) to scan function images when they are pushed to a function's repository. The function images are scanned for security vulnerabilities published in the publicly available Common Vulnerabilities and Exposures (CVE) database. You enable function image scanning by adding an image scanner to the function's repository. From then on, any images pushed to that repository are scanned for vulnerabilities by the image scanner. If the repository already contains images, the four most recently pushed images are immediately scanned for vulnerabilities. Always use the latest FDK build-time and runtime base images to reduce the number of known vulnerabilities included in an image and reported in the scan results. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on setting up vulnerability scanning for Cloud Functions refer to the Scanning Function Images for Vulnerabilities section of the Oracle Cloud Infrastructure Documentation for Functions.",
                            "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsimagescanning.htm"
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
                        "AssetComponent": "Function"
                    },
                    "Resources": [
                        {
                            "Type": "OciCloudFunctionsFunction",
                            "Id": funcId,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "TenancyId": ociTenancyId,
                                    "CompartmentId": compartmentId,
                                    "Region": ociRegionName,
                                    "Name": funcName,
                                    "Id": funcId,
                                    "Image": funcImage,
                                    "ApplicationId": appId,
                                    "LifecycleState": lifecycleState,
                                    "CreatedAt": funcCreatedAt
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.CM-8",
                            "NIST CSF V1.1 ID.RA-1",
                            "NIST SP 800-53 Rev. 4 CA-2",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 CA-8",
                            "NIST SP 800-53 Rev. 4 RA-3",
                            "NIST SP 800-53 Rev. 4 RA-5",
                            "NIST SP 800-53 Rev. 4 SA-5",
                            "NIST SP 800-53 Rev. 4 SA-11",
                            "NIST SP 800-53 Rev. 4 SI-2",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AICPA TSC CC3.2",
                            "AICPA TSC CC7.1",
                            "ISO 27001:2013 A.12.6.1",
                            "ISO 27001:2013 A.12.6.4",
                            "ISO 27001:2013 A.18.2.3"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{funcId}/oci-cloud-functions-use-scanned-images-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{funcId}/oci-cloud-functions-use-scanned-images-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[OCI.CloudFunctions.5] Oracle Cloud Functions should only use images that are scanned for vulnerabilities",
                    "Description": f" Oracle Cloud Function {funcName} in Compartment {compartmentId} in {ociRegionName} does use an image that is scanned for vulnerabilities.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on setting up vulnerability scanning for Cloud Functions refer to the Scanning Function Images for Vulnerabilities section of the Oracle Cloud Infrastructure Documentation for Functions.",
                            "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsimagescanning.htm"
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
                        "AssetComponent": "Function"
                    },
                    "Resources": [
                        {
                            "Type": "OciCloudFunctionsFunction",
                            "Id": funcId,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "TenancyId": ociTenancyId,
                                    "CompartmentId": compartmentId,
                                    "Region": ociRegionName,
                                    "Name": funcName,
                                    "Id": funcId,
                                    "Image": funcImage,
                                    "ApplicationId": appId,
                                    "LifecycleState": lifecycleState,
                                    "CreatedAt": funcCreatedAt
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.CM-8",
                            "NIST CSF V1.1 ID.RA-1",
                            "NIST SP 800-53 Rev. 4 CA-2",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 CA-8",
                            "NIST SP 800-53 Rev. 4 RA-3",
                            "NIST SP 800-53 Rev. 4 RA-5",
                            "NIST SP 800-53 Rev. 4 SA-5",
                            "NIST SP 800-53 Rev. 4 SA-11",
                            "NIST SP 800-53 Rev. 4 SI-2",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AICPA TSC CC3.2",
                            "AICPA TSC CC7.1",
                            "ISO 27001:2013 A.12.6.1",
                            "ISO 27001:2013 A.12.6.4",
                            "ISO 27001:2013 A.18.2.3"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("oci.cloudfunctions")
def oci_cloud_functions_provisioned_concurrency_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.CloudFunctions.6] Oracle Cloud Functions should consider using provisioned concurrency to reduce latency
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for application in get_cloud_function_apps(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        if not application["functions"]:
            continue
        
        compartmentId = application["compartment_id"]
        # Run through the actual functions
        for function in application["functions"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(function,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            appId = function["application_id"]
            funcName = function["display_name"]
            funcId = function["id"]
            funcImage = function["image"]
            funcCreatedAt = str(function["time_created"])
            lifecycleState = function["lifecycle_state"]

            if function["provisioned_concurrency_config"]["strategy"] is None:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{funcId}/oci-cloud-functions-provisioned-concurrency-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{funcId}/oci-cloud-functions-provisioned-concurrency-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[OCI.CloudFunctions.6] Oracle Cloud Functions should consider using provisioned concurrency to reduce latency",
                    "Description": f" Oracle Cloud Function {funcName} in Compartment {compartmentId} in {ociRegionName} does not use provisioned concurrency to reduce latency. When a function is invoked for the first time (referred to as a 'cold start'), OCI Functions provisions the function invocation with the execution infrastructure it requires. The execution infrastructure includes the compute and network resources necessary to successfully invoke the function. The initial provisioning, and hence the response to the first invocation, might take some variable amount of time (potentially several seconds, or longer). The initial function invocation's execution infrastructure is retained for a period of time (referred to as the 'idle time'), for use by subsequent invocations of the same function. When a subsequent function invocation is able to make use of existing infrastructure (referred to as a 'hot start'), there is usually a sub-second response time to the function invocation. It's common that you'll want consistent, sub-second, responses to function invocations. To minimize any latency associated with initial provisioning and to ensure hot starts, you can enable provisioned concurrency for a function. Provisioned concurrency is the ability of OCI Functions to always have available the execution infrastructure for at least a certain minimum number of concurrent function invocations. Provisioned concurrency is measured in 'provisioned concurrency units' (PCUs). The total number of PCUs available depends on the size of the function, the tenancy limit, and whether provisioned concurrency has been enabled for other functions in the tenancy. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on setting up provisioned concurrency for Cloud Functions refer to the Reducing Initial Latency Using Provisioned Concurrency section of the Oracle Cloud Infrastructure Documentation for Functions.",
                            "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsusingprovisionedconcurrency.htm"
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
                        "AssetComponent": "Function"
                    },
                    "Resources": [
                        {
                            "Type": "OciCloudFunctionsFunction",
                            "Id": funcId,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "TenancyId": ociTenancyId,
                                    "CompartmentId": compartmentId,
                                    "Region": ociRegionName,
                                    "Name": funcName,
                                    "Id": funcId,
                                    "Image": funcImage,
                                    "ApplicationId": appId,
                                    "LifecycleState": lifecycleState,
                                    "CreatedAt": funcCreatedAt
                                }
                            }
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
                            "ISO 27001:2013 A.17.2.1"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{funcId}/oci-cloud-functions-provisioned-concurrency-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{funcId}/oci-cloud-functions-provisioned-concurrency-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[OCI.CloudFunctions.6] Oracle Cloud Functions should consider using provisioned concurrency to reduce latency",
                    "Description": f" Oracle Cloud Function {funcName} in Compartment {compartmentId} in {ociRegionName} does use provisioned concurrency to reduce latency.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on setting up provisioned concurrency for Cloud Functions refer to the Reducing Initial Latency Using Provisioned Concurrency section of the Oracle Cloud Infrastructure Documentation for Functions.",
                            "Url": "https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsusingprovisionedconcurrency.htm"
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
                        "AssetComponent": "Function"
                    },
                    "Resources": [
                        {
                            "Type": "OciCloudFunctionsFunction",
                            "Id": funcId,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "TenancyId": ociTenancyId,
                                    "CompartmentId": compartmentId,
                                    "Region": ociRegionName,
                                    "Name": funcName,
                                    "Id": funcId,
                                    "Image": funcImage,
                                    "ApplicationId": appId,
                                    "LifecycleState": lifecycleState,
                                    "CreatedAt": funcCreatedAt
                                }
                            }
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

## END ??