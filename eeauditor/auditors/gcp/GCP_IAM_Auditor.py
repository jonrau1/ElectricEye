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
from check_register import CheckRegister
import googleapiclient.discovery
import base64
import json

registry = CheckRegister()

def get_service_accounts(cache: dict, gcpProjectId, gcpCredentials) -> list[dict] | dict:
    """Get all service accounts for a given project"""
    response = cache.get("get_bigquery_tables")
    if response:
        return response
    
    service = googleapiclient.discovery.build("iam", "v1", credentials=gcpCredentials)
    request = service.projects().serviceAccounts().list(name=f"projects/{gcpProjectId}").execute()
    
    serviceAccounts = request.get("accounts", [])
    
    if serviceAccounts:
        cache["get_bigquery_tables"] = serviceAccounts
        return cache["get_bigquery_tables"]
    else:
        return {}
    
def get_service_account_keys(serviceAccountEmail: str, gcpCredentials) -> list[dict]:
    """Gets keys for a given service account"""
    service = googleapiclient.discovery.build("iam", "v1", credentials=gcpCredentials)
    request = service.projects().serviceAccounts().keys().list(
        name=f"projects/-/serviceAccounts/{serviceAccountEmail}",
        keyTypes="USER_MANAGED"
    ).execute()

    serviceAccountKeys = request.get("keys", [])

    return serviceAccountKeys

@registry.register_check("gcp.iam")
def gcp_service_account_no_user_managed_keys_check(cache: dict, awsAccountId, awsRegion, awsPartition, gcpProjectId, gcpCredentials):
    """[GCP.IAM.1] Ensure that there are not user-managed keys for service accounts"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.UTC).replace(tzinfo=datetime.timezone.utc).isoformat()
    # Loop the datasets
    for serviceAccount in get_service_accounts(cache, gcpProjectId, gcpCredentials):
        displayName = serviceAccount["displayName"]
        serviceAccountId = serviceAccount["uniqueId"]
        serviceAccountName = serviceAccount["name"]
        # If there are keys for the service account, fail the check
        userManagedKeyFail = False
        keys = get_service_account_keys(serviceAccount["email"], gcpCredentials)
        if keys:
            userManagedKeyFail = True
        # add the keys if they exist to the asset
        serviceAccount["keys"] = keys
        assetJson = json.dumps(serviceAccount,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)

        # this is a failing check
        if userManagedKeyFail:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{serviceAccountName}/gcp-service-account-no-user-managed-keys-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceAccountName}/gcp-service-account-no-user-managed-keys-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[GCP.IAM.1] Ensure that there are not user-managed keys for service accounts",
                "Description": f"GCP Service Account {displayName} (Unique ID: {serviceAccountId}) contains at least one user-managed key. User managed service accounts should not have user-managed keys, Anyone who has access to the keys will be able to access resources through the service account. GCP-managed keys are used by Cloud Platform services such as App Engine and Compute Engine. These keys cannot be downloaded. Google will keep the keys and automatically rotate them on an approximately weekly basis. User-managed keys are created, downloadable, and managed by users. They expire 10 years from creation. Even with key owner precautions, keys can be easily leaked by common development malpractices like checking keys into the source code or leaving them in the Downloads directory, or accidentally leaving them on support blogs/channels. It is rather ironic to include this check, given that I require the usage of Service Account keys after, better to be safe than sorry I guess! Refer to the remediation instructions if keeping the table is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on best practices for service accounts refer to the Best practices for using service accounts section of the GCP IAM documentation.",
                        "Url": "https://cloud.google.com/iam/docs/best-practices-service-accounts"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": "global",
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Google Cloud IAM",
                    "AssetComponent": "Service Account"
                },
                "Resources": [
                    {
                        "Type": "GcpIamServiceAccount",
                        "Id": serviceAccountName,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ProjectId": gcpProjectId,
                                "ServiceAccountName": serviceAccountName,
                                "ServiceAccountId": serviceAccountId,
                                "DisplayName": displayName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3",
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "CIS Google Cloud Platform Foundation Benchmark V2.0 1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{serviceAccountName}/gcp-service-account-no-user-managed-keys-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceAccountName}/gcp-service-account-no-user-managed-keys-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.IAM.1] Ensure that there are not user-managed keys for service accounts",
                "Description": f"GCP Service Account {displayName} (Unique ID: {serviceAccountId}) does not contain any user-managed keys.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on best practices for service accounts refer to the Best practices for using service accounts section of the GCP IAM documentation.",
                        "Url": "https://cloud.google.com/iam/docs/best-practices-service-accounts"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": "global",
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Google Cloud IAM",
                    "AssetComponent": "Service Account"
                },
                "Resources": [
                    {
                        "Type": "GcpIamServiceAccount",
                        "Id": serviceAccountName,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ProjectId": gcpProjectId,
                                "ServiceAccountName": serviceAccountName,
                                "ServiceAccountId": serviceAccountId,
                                "DisplayName": displayName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3",
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "CIS Google Cloud Platform Foundation Benchmark V2.0 1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding


# end