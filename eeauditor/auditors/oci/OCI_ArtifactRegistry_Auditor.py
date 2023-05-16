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

def get_virustotal_api_key():
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
        
    return apiKey

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

## END ??