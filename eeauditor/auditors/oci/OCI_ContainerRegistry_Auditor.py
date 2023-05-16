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

def get_container_repos(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_container_repos")
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

    ociContainerRepos = []

    for compartment in ociCompartments:
        for repo in process_response(artifactClient.list_container_repositories(compartment_id=compartment).data)["items"]:
            ociContainerRepos.append(
                process_response(
                    artifactClient.get_container_repository(repository_id=repo["id"]).data
                )
            )

    cache["get_container_repos"] = ociContainerRepos
    return cache["get_container_repos"]

def get_artifact_repos(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_artifact_repos")
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

    ociArtifactRepos = []

    # It looks similar to containers, but the plain repository means an Aritfact Repository
    for compartment in ociCompartments:
        for repo in process_response(artifactClient.list_repositories(compartment_id=compartment).data)["items"]:
            ociArtifactRepos.append(
                process_response(
                    artifactClient.get_repository(repository_id=repo["id"]).data
                )
            )

    cache["get_artifact_repos"] = ociArtifactRepos
    return cache["get_artifact_repos"]

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

    vssClient = oci.vulnerability_scanning.VulnerabilityScanningClient(config)

    scannedContainerRegistryRepos = []

    # It looks similar to containers, but the plain repository means an Aritfact Repository
    for compartment in ociCompartments:
        for targets in process_response(vssClient.list_container_scan_targets(compartment_id=compartment).data)["items"]:
            for targetrepo in targets["target_registry"]["repositories"]:
                if targetrepo not in scannedContainerRegistryRepos:
                    scannedContainerRegistryRepos.append(targetrepo)

    cache["get_scanned_repositories"] = scannedContainerRegistryRepos
    return cache["get_scanned_repositories"]

def get_repository_images(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_repository_images")
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

    containerRegistryImages = []

    # It looks similar to containers, but the plain repository means an Aritfact Repository
    for compartment in ociCompartments:
        for image in process_response(artifactClient.list_container_images(compartment_id=compartment).data)["items"]:
            signingData = process_response(
                artifactClient.list_container_image_signatures(compartment_id=compartment, image_id=image["id"]).data
            )
            image["container_image_signatures"] = signingData["items"]

            containerRegistryImages.append(image)

    cache["get_repository_images"] = containerRegistryImages
    return cache["get_repository_images"]

@registry.register_check("oci.containerregistry")
def oci_container_registry_review_public_repos_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ContainerRegistry.1] Oracle Container Registry repositories that are public should be reviewed
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for repo in get_container_repos(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(repo,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = repo["compartment_id"]
        repoId = repo["id"]
        repoName = repo["display_name"]
        lifecycleState = repo["lifecycle_state"]
        createdAt = str(repo["time_created"])

        if repo["is_public"] is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-container-registry-repo-public-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-container-registry-repo-public-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.ContainerRegistry.1] Oracle Container Registry repositories that are public should be reviewed",
                "Description": f"Oracle Container Registry repository {repoName} in Compartment {compartmentId} in {ociRegionName} is currently configured to be public. Regarding Public Repositories, you can only make the new repository public if you belong to the tenancy's Administrators group or have been granted the REPOSITORY_MANAGE permission. If you make the new repository public, any user with internet access and knowledge of the appropriate URL will be able to pull images from the repository. If you make the repository private, you (along with users belonging to the tenancy's Administrators group) will be able to perform any operation on the repository. There are many use cases where having a Public repository is viable such as providing an image you build as part of an open source, research, or product offering - however - you should review the repository and understand the business or mission context. Additionally, even if a repository should be public ensure that images are reviewed for sensitive or confidential information, vulnerabilities, and are signed if at all possible. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If necessary a repository that is public can be made private, and vice versa, for more information see the Editing a Repository section of the Oracle Cloud Infrastructure Documentation for Container Registry.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Registry/Tasks/edit-repository.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle Container Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "OciContainerRegistryRepository",
                        "Id": repoId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": repoName,
                                "Id": repoId,
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-container-registry-repo-public-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-container-registry-repo-public-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ContainerRegistry.1] Oracle Container Registry repositories that are public should be reviewed",
                "Description": f"Oracle Container Registry repository {repoName} in Compartment {compartmentId} in {ociRegionName} is currently configured to be private.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If necessary a repository that is public can be made private, and vice versa, for more information see the Editing a Repository section of the Oracle Cloud Infrastructure Documentation for Container Registry.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Registry/Tasks/edit-repository.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle Container Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "OciContainerRegistryRepository",
                        "Id": repoId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": repoName,
                                "Id": repoId,
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

@registry.register_check("oci.containerregistry")
def oci_container_registry_repos_vulnerability_scanning_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ContainerRegistry.2] Oracle Container Registry repositories should have an Oracle Vulnerability Scanning Service (VSS) target association
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Get scanned Repos
    scannedRepos = get_scanned_repositories(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint)

    for repo in get_container_repos(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(repo,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = repo["compartment_id"]
        repoId = repo["id"]
        repoName = repo["display_name"]
        lifecycleState = repo["lifecycle_state"]
        createdAt = str(repo["time_created"])

        if repoName not in scannedRepos:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-container-registry-repos-vuln-scan-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-container-registry-repos-vuln-scan-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.ContainerRegistry.2] Oracle Container Registry repositories should have an Oracle Vulnerability Scanning Service (VSS) target association",
                "Description": f"Oracle Container Registry repository {repoName} in Compartment {compartmentId} in {ociRegionName} does not have an Oracle Vulnerability Scanning Service (VSS) target association. It is not uncommon for the operating system packages included in images to have vulnerabilities. Managing these vulnerabilities enables you to strengthen the security posture of your system, and respond quickly when new vulnerabilities are discovered. You can setup your Repositories to scan images in a repository for security vulnerabilities published in the publicly available Common Vulnerabilities and Exposures (CVE) database. You enable image scanning by adding an image scanner to a repository. From then on, any images pushed to the repository are scanned for vulnerabilities by the image scanner. If the repository already contains images, the four most recently pushed images are immediately scanned for vulnerabilities. Whenever new vulnerabilities are added to the CVE database, Container Registry automatically re-scans images in repositories that have scanning enabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up Oracle Vulnerability Scanning Service and having your Container Registry Repositories scanned for CVEs see the Container Image Targets section of the Oracle Cloud Infrastructure Documentation for Vulnerability Scanning.",
                        "Url": "https://docs.oracle.com/iaas/scanning/using/managing-image-targets.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle Container Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "OciContainerRegistryRepository",
                        "Id": repoId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": repoName,
                                "Id": repoId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-container-registry-repos-vuln-scan-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-container-registry-repos-vuln-scan-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ContainerRegistry.2] Oracle Container Registry repositories should have an Oracle Vulnerability Scanning Service (VSS) target association",
                "Description": f"Oracle Container Registry repository {repoName} in Compartment {compartmentId} in {ociRegionName} does have an Oracle Vulnerability Scanning Service (VSS) target association.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up Oracle Vulnerability Scanning Service and having your Container Registry Repositories scanned for CVEs see the Container Image Targets section of the Oracle Cloud Infrastructure Documentation for Vulnerability Scanning.",
                        "Url": "https://docs.oracle.com/iaas/scanning/using/managing-image-targets.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle Container Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "OciContainerRegistryRepository",
                        "Id": repoId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": repoName,
                                "Id": repoId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.containerregistry")
def oci_container_registry_images_signed_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ContainerRegistry.3] Oracle Container Registry images should be signed with an image signature
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for image in get_repository_images(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(image,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = image["compartment_id"]
        imageId = image["id"]
        imageName = image["display_name"]
        repoId = image["repository_id"]
        repoName = image["repository_name"]
        lifecycleState = image["lifecycle_state"]
        createdAt = str(image["time_created"])

        if not image["container_image_signatures"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{imageId}/oci-container-registry-image-signing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{imageId}/oci-container-registry-image-signing-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.ContainerRegistry.3] Oracle Container Registry images should be signed with an image signature",
                "Description": f"Oracle Container Registry image {imageName} from Repository {repoName} in Compartment {compartmentId} in {ociRegionName} is not signed with an image signature. For compliance and security reasons, system administrators often want to deploy software into a production system only when they are satisfied that the software comes from a trusted source and has not been modified since it was published, compromising its integrity. To meet these requirements, you can sign images, signed images provide a way to verify both the source of an image and its integrity. Container Registry enables users or systems to push images to the registry and then sign them using a master encryption key obtained from Oracle Cloud Infrastructure Vault, creating an image signature. An image signature associates a signed image with a particular master encryption key used to sign the image. An image can have multiple signatures, each created using a different master encryption key. Users or systems pulling a signed image from Container Registry can be confident both that the source of the image is trusted, and that the image's integrity has not been compromised. To further enhance compliance and security, clients can be configured to only pull signed images from the registry. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on signing images and signature verification refer to the Signing Images for Security section of the Oracle Cloud Infrastructure Documentation for Container Registry.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Registry/Tasks/registrysigningimages_topic.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle Container Registry",
                    "AssetComponent": "Image"
                },
                "Resources": [
                    {
                        "Type": "OciContainerRegistryImage",
                        "Id": imageId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": imageName,
                                "Id": imageId,
                                "LifecycleState": lifecycleState,
                                "RepositoryId": repoId,
                                "RepositoryName": repoName,
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
                        "ISO 27001:2013 A.14.1.3"
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{imageId}/oci-container-registry-image-signing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{imageId}/oci-container-registry-image-signing-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ContainerRegistry.3] Oracle Container Registry images should be signed with an image signature",
                "Description": f"Oracle Container Registry image {imageName} from Repository {repoName} in Compartment {compartmentId} in {ociRegionName} is signed with an image signature.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on signing images and signature verification refer to the Signing Images for Security section of the Oracle Cloud Infrastructure Documentation for Container Registry.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Registry/Tasks/registrysigningimages_topic.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle Container Registry",
                    "AssetComponent": "Image"
                },
                "Resources": [
                    {
                        "Type": "OciContainerRegistryImage",
                        "Id": imageId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": imageName,
                                "Id": imageId,
                                "LifecycleState": lifecycleState,
                                "RepositoryId": repoId,
                                "RepositoryName": repoName,
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
                        "ISO 27001:2013 A.14.1.3"
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.15.2.2"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??