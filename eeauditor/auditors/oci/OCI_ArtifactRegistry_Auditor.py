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

import tomli
import os
import oci
from oci.config import validate_config
import vt
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def get_virustotal_api_key(cache):

    response = cache.get("get_virustotal_api_key")
    if response:
        return response

    import sys
    import boto3
    from botocore.exceptions import ClientError

    validCredLocations = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

    # Get the absolute path of the current directory
    currentDir = os.path.abspath(os.path.dirname(__file__))
    # Go two directories back to /eeauditor/
    twoBack = os.path.abspath(os.path.join(currentDir, "../../"))

    # TOML is located in /eeauditor/ directory
    tomlFile = f"{twoBack}/external_providers.toml"
    with open(tomlFile, "rb") as f:
        data = tomli.load(f)

    # Parse from [global] to determine credential location of PostgreSQL Password
    credLocation = data["global"]["credentials_location"]
    vtCredValue = data["global"]["virustotal_api_key_value"]
    if credLocation not in validCredLocations:
        print(f"Invalid option for [global.credLocation]. Must be one of {str(validCredLocations)}.")
        sys.exit(2)
    if not vtCredValue:
        apiKey = None
    else:

        # Boto3 Clients
        ssm = boto3.client("ssm")
        asm = boto3.client("secretsmanager")

        # Retrieve API Key
        if credLocation == "CONFIG_FILE":
            apiKey = vtCredValue

        # Retrieve the credential from SSM Parameter Store
        elif credLocation == "AWS_SSM":
            
            try:
                apiKey = ssm.get_parameter(
                    Name=vtCredValue,
                    WithDecryption=True
                )["Parameter"]["Value"]
            except ClientError as e:
                print(f"Error retrieving API Key from SSM, skipping all Shodan checks, error: {e}")
                apiKey = None

        # Retrieve the credential from AWS Secrets Manager
        elif credLocation == "AWS_SECRETS_MANAGER":
            try:
                apiKey = asm.get_secret_value(
                    SecretId=vtCredValue,
                )["SecretString"]
            except ClientError as e:
                print(f"Error retrieving API Key from ASM, skipping all Shodan checks, error: {e}")
                apiKey = None
        
    cache["get_virustotal_api_key"] = apiKey
    return cache["get_virustotal_api_key"]

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

    for compartment in ociCompartments:
        for repo in process_response(artifactClient.list_repositories(compartment_id=compartment).data)["items"]:
            # Get all of the Artifacts in the actual Repository and add it as a new list - this way we can avoid
            # multiple API calls
            artifactStorage = process_response(
                artifactClient.list_generic_artifacts(
                    compartment_id=compartment, repository_id=repo["id"]).data
                )["items"]
            repo["generic_artifacts"] = artifactStorage
            ociArtifactRepos.append(repo)

    cache["get_artifact_repos"] = ociArtifactRepos
    return cache["get_artifact_repos"]

@registry.register_check("oci.artifactregistry")
def oci_artifact_registry_empty_repository_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ArtifactRegistry.1] Oracle Artifact Registry repositories that are empty should be reviewed for deletion
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for repo in get_artifact_repos(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(repo,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = repo["compartment_id"]
        repoId = repo["id"]
        repoName = repo["display_name"]
        lifecycleState = repo["lifecycle_state"]
        createdAt = str(repo["time_created"])

        if not repo["generic_artifacts"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-artifact-registry-empty-repo-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-artifact-registry-empty-repo-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.ArtifactRegistry.1] Oracle Artifact Registry repositories that are empty should be reviewed for deletion",
                "Description": f"Oracle Artifact Registry repository {repoName} in Compartment {compartmentId} in {ociRegionName} does not contain any artifacts and should be reviewed for deletion. An artifact is a software package, library, zip file, or any other type of file used for deploying applications. Examples are Python or Maven libraries. Artifacts are grouped into repositories, which are collections of related artifacts. For example, you could group several versions of a Maven artifact in a Maven repository, or upload your Python libraries to a Python repository. Having an empty repository can be innocuous as it may be staged before development teams upload any artifacts to it, however, empty repositories could potentially be filled with malicious packages if adversaries were to gain access to it and trick developers into using it. That scenario is highly unlikely to occur but proper hygeine in your environment means using only the services and components absolutely needed and removing orphaned or derelict resources. At the very least, your CFO or VP of IT Finance may thank you. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on repository deletion refer to the Deleting a Repository in Artifact Registry section of the Oracle Cloud Infrastructure Documentation for Artifact Registry.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/artifacts/delete-repo.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "Oracle Artifact Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "OciArtifactRegistryRepository",
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
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 SA-13",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-artifact-registry-empty-repo-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-artifact-registry-empty-repo-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ArtifactRegistry.1] Oracle Artifact Registry repositories that are empty should be reviewed for deletion",
                "Description": f"Oracle Artifact Registry repository {repoName} in Compartment {compartmentId} in {ociRegionName} does contain artifacts.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on repository deletion refer to the Deleting a Repository in Artifact Registry section of the Oracle Cloud Infrastructure Documentation for Artifact Registry.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/artifacts/delete-repo.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "Oracle Artifact Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "OciArtifactRegistryRepository",
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
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 SA-13",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.artifactregistry")
def oci_artifact_registry_immutable_artifacts_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ArtifactRegistry.2] Oracle Artifact Registry repositories should consider enabling immutable artifacts
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for repo in get_artifact_repos(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(repo,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = repo["compartment_id"]
        repoId = repo["id"]
        repoName = repo["display_name"]
        lifecycleState = repo["lifecycle_state"]
        createdAt = str(repo["time_created"])

        if repo["is_immutable"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-artifact-registry-immutable-artifacts-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-artifact-registry-immutable-artifacts-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.ArtifactRegistry.2] Oracle Artifact Registry repositories should consider enabling immutable artifacts",
                "Description": f"Oracle Artifact Registry repository {repoName} in Compartment {compartmentId} in {ociRegionName} does not enable immutable artifacts. When you create a repository, you can designate it as immutable, which means that the artifacts uploaded to it become immutable. These artifacts are used as-is and can't be replaced. Immutable repositories ensure the integrity of the artifacts. Some common use cases which call for immutable artifacts are deployment rollbacks where you need to revert to an exact version of a release and ensure that it has not been changed nor otherwise tampered with or when contributing code or artifacts you want to ensure that an important function, image, or artifact cannot be overwitten. From a security perspective, immutable artifacts provide a guarantee on integrity, or in other words, ensure that the artifact has not been tampered with since it was built and that it cannot be overwritten. In Oracle Artifact Registry, an immutable artifact can be deleted but can't be replaced. If you delete an immutable artifact, you cannot assign its name to another artifact. Therefore, you cannot upload a new artifact and assign it the deleted artifact's path and version. However, you can give it the same path with a new version. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on immutable repositories refer to the Immutable Artifacts in Artifact Registry section of the Oracle Cloud Infrastructure Documentation for Artifact Registry.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/artifacts/concepts.htm#immutable-artifacts",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "Oracle Artifact Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "OciArtifactRegistryRepository",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-artifact-registry-immutable-artifacts-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{repoId}/oci-artifact-registry-immutable-artifacts-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ArtifactRegistry.2] Oracle Artifact Registry repositories should consider enabling immutable artifacts",
                "Description": f"Oracle Artifact Registry repository {repoName} in Compartment {compartmentId} in {ociRegionName} does enable immutable artifacts.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on immutable repositories refer to the Immutable Artifacts in Artifact Registry section of the Oracle Cloud Infrastructure Documentation for Artifact Registry.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/artifacts/concepts.htm#immutable-artifacts",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "Oracle Artifact Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "OciArtifactRegistryRepository",
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

@registry.register_check("oci.artifactregistry")
def oci_artifact_registry_artifact_virustotal_scan_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ArtifactRegistry.3] Oracle Artifact Registry artifacts should be scanned for malware and viruses
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for repo in get_artifact_repos(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # Skip empty repos
        if not repo["generic_artifacts"]:
            continue
        # Skip if the API key is empty
        vtApiKey = get_virustotal_api_key(cache)
        if vtApiKey is None:
            continue

        # B64 encode all of the details for the Asset
        # in this case we've already written the artifacts into the `repo` object anyway
        assetJson = json.dumps(repo,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = repo["compartment_id"]
        repoId = repo["id"]
        repoName = repo["display_name"]
        lifecycleState = repo["lifecycle_state"]
        

        # Begin the finding evaluation here using a context manager for VT based on the SHA256 hash that OCAR calculates
        # if an Exception is returned it is typically because there is not a match in VT but it could also
        # be due to limits -- as ElectricEye cannot discern API-key tier or burst limit -- we will just ignore it
        # also, the evaluation is hard-coded to trip on >=5 suspicious or >=2 malicious findings in VT
        for artifact in repo["generic_artifacts"]:
            artifactName = artifact["display_name"]
            artifactId = artifact["id"]
            artifactHash = artifact["sha256"]
            createdAt = str(repo["time_created"])

            # VT Context manager
            with vt.Client(vtApiKey) as client:
                try:
                    file = client.get_object(f"/files/{artifactHash}")
                    analysis = file.last_analysis_stats
                    maliciousFindings = int(analysis["malicious"])
                    suspiciousFidnings = int(analysis["suspicious"])
                    if suspiciousFidnings >= 5 or maliciousFindings >= 2:
                        fileMalicious = True
                    else:
                        fileMalicious = False
                except vt.APIError:
                    fileMalicious = False
                    # this more or less resembles the APIError: ('NotFoundError', 'File "somehash436692c01b87f0bac80e5fchash3ed" not found')
                    analysis = {f"NotFoundError: File {artifactHash} not found"}

                # Now we can create findings
                if fileMalicious is True:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{artifactId}/oci-artifact-registry-artifact-malware-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{artifactId}/oci-artifact-registry-artifact-malware-check",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "CRITICAL"},
                        "Confidence": 99,
                        "Title": "[OCI.ArtifactRegistry.3] Oracle Artifact Registry artifacts should be scanned for malware and viruses",
                        "Description": f"Oracle Artifact Registry artifact {artifactName} in the {repoName} repository in Compartment {compartmentId} in {ociRegionName} matched multiple detectors in VirusTotal for evidence of malware or viruses. The file analysis summary for the artifact was {str(analysis)}. VirusTotal inspects items with over 70 antivirus scanners and URL/domain blocklisting services, in addition to a myriad of tools to extract signals from the studied content. Any user can select a file from their computer using their browser and send it to VirusTotal. Malware signatures are updated frequently by VirusTotal as they are distributed by antivirus companies, this ensures that the VirusTotal service uses the latest signature sets. While there can be false positives due to behavioral analysis or matching on older hashes, it is less often the case, and the artifact should be destoryed if not cordoned off for further analysis. Oracle Events for Artifact Registry can be used to find who uploaded the artifacts and how many times the object was donwloaded. Refer to the remediation instructions if this configuration is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "The most important step is barring access to the Registry if not outright destorying the artifact. For more information on using Oracle Events to investigate the artifact in question refer to the Artifact Registry Events section of the Oracle Cloud Infrastructure Documentation for Artifact Registry.",
                                "Url": "https://docs.oracle.com/en-us/iaas/Content/artifacts/events.htm",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "OCI",
                            "ProviderType": "CSP",
                            "ProviderAccountId": ociTenancyId,
                            "AssetRegion": ociRegionName,
                            "AssetDetails": assetB64,
                            "AssetClass": "Developer Tools",
                            "AssetService": "Oracle Artifact Registry",
                            "AssetComponent": "Artifact"
                        },
                        "Resources": [
                            {
                                "Type": "OciArtifactRegistryArtifact",
                                "Id": artifactId,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "TenancyId": ociTenancyId,
                                        "CompartmentId": compartmentId,
                                        "Region": ociRegionName,
                                        "RepositoryName": repoName,
                                        "RepositoryId": repoId,
                                        "RepositoryLifecycleState": lifecycleState,
                                        "ArtifactCreatedAt": createdAt,
                                        "ArtifactId": artifactId,
                                        "Sha256": artifactHash,
                                        "ArtifactName": artifactName
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 ID.SC-2",
                                "NIST CSF V1.1 PR.DS-6",
                                "NIST CSF V1.1 DE.CM-4"
                                "NIST SP 800-53 Rev. 4 RA-2",
                                "NIST SP 800-53 Rev. 4 RA-3",
                                "NIST SP 800-53 Rev. 4 PM-9",
                                "NIST SP 800-53 Rev. 4 SA-12",
                                "NIST SP 800-53 Rev. 4 SA-14",
                                "NIST SP 800-53 Rev. 4 SA-15",
                                "NIST SP 800-53 Rev. 4 SI-3",
                                "NIST SP 800-53 Rev. 4 SI-7",
                                "AICPA TSC CC6.8",
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
                        "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{artifactId}/oci-artifact-registry-artifact-malware-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{artifactId}/oci-artifact-registry-artifact-malware-check",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[OCI.ArtifactRegistry.3] Oracle Artifact Registry artifacts should be scanned for malware and viruses",
                        "Description": f"Oracle Artifact Registry artifact {artifactName} in the {repoName} repository in Compartment {compartmentId} in {ociRegionName} did not match multiple detectors in VirusTotal for evidence of malware or viruses. The file analysis summary for the artifact was {str(analysis)}.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "The most important step is barring access to the Registry if not outright destorying the artifact. For more information on using Oracle Events to investigate the artifact in question refer to the Artifact Registry Events section of the Oracle Cloud Infrastructure Documentation for Artifact Registry.",
                                "Url": "https://docs.oracle.com/en-us/iaas/Content/artifacts/events.htm",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "OCI",
                            "ProviderType": "CSP",
                            "ProviderAccountId": ociTenancyId,
                            "AssetRegion": ociRegionName,
                            "AssetDetails": assetB64,
                            "AssetClass": "Developer Tools",
                            "AssetService": "Oracle Artifact Registry",
                            "AssetComponent": "Artifact"
                        },
                        "Resources": [
                            {
                                "Type": "OciArtifactRegistryArtifact",
                                "Id": artifactId,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "TenancyId": ociTenancyId,
                                        "CompartmentId": compartmentId,
                                        "Region": ociRegionName,
                                        "RepositoryName": repoName,
                                        "RepositoryId": repoId,
                                        "RepositoryLifecycleState": lifecycleState,
                                        "ArtifactCreatedAt": createdAt,
                                        "ArtifactId": artifactId,
                                        "Sha256": artifactHash,
                                        "ArtifactName": artifactName
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 ID.SC-2",
                                "NIST CSF V1.1 PR.DS-6",
                                "NIST CSF V1.1 DE.CM-4"
                                "NIST SP 800-53 Rev. 4 RA-2",
                                "NIST SP 800-53 Rev. 4 RA-3",
                                "NIST SP 800-53 Rev. 4 PM-9",
                                "NIST SP 800-53 Rev. 4 SA-12",
                                "NIST SP 800-53 Rev. 4 SA-14",
                                "NIST SP 800-53 Rev. 4 SA-15",
                                "NIST SP 800-53 Rev. 4 SI-3",
                                "NIST SP 800-53 Rev. 4 SI-7",
                                "AICPA TSC CC6.8",
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