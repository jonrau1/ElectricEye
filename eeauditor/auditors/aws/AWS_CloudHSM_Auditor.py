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
import base64
import json

registry = CheckRegister()

def describe_clusters(cache, session):
    cloudhsm = session.client("cloudhsmv2")
    response = cache.get("describe_clusters")
    if response:
        return response
    cache["describe_clusters"] = cloudhsm.describe_clusters()
    return cache["describe_clusters"]

@registry.register_check("cloudhsm")
def cloudhsm_cluster_degradation_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudHsm.1] CloudHsm clusters should not be degraded"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for clstr in describe_clusters(cache, session)["Clusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clstr,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = clstr["ClusterId"]
        if clstr["State"] != "DEGRADED":
            #Passing Check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterId + "/cloudhsm-cluster-degradation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudHsm.1] CloudHsm clusters should not be in a degraded state",
                "Description": f"CloudHSM cluster {clusterId} is not in a degraded state",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on HSM Clusters refer to the AWS CloudHsm User Guide on managing cloudhsm clusters",
                        "Url": "https://docs.aws.amazon.com/cloudhsm/latest/userguide/manage-clusters.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "AWS CloudHSM",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudHsmCluster",
                        "Id": clusterId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCloudHsmCluster": {"ClusterId": clusterId}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.AE-5",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.DP-2",                        
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-6",
                        "AICPA TSC CC4.1",
                        "AICPA TSC CC5.1",
                        "ISO 27001:2013 A.10.1.2",
                        "ISO 27001:2013 A.12.4.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterId + "/cloudhsm-cluster-degradation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[CloudHsm.1] CloudHsm clusters should not be in a degraded state",
                "Description": f"CloudHSM cluster {clusterId} is in a degraded state",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on HSM Clusters refer to the AWS CloudHsm User Guide on managing cloudhsm clusters",
                        "Url": "https://docs.aws.amazon.com/cloudhsm/latest/userguide/manage-clusters.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "AWS CloudHSM",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudHsmCluster",
                        "Id": clusterId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCloudHsmCluster": {"ClusterId": clusterId}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.AE-5",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.DP-2",                        
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-6",
                        "AICPA TSC CC4.1",
                        "AICPA TSC CC5.1",
                        "ISO 27001:2013 A.10.1.2",
                        "ISO 27001:2013 A.12.4.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("cloudhsm")
def cloudhsm_hsm_degradation_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudHsm.2] CloudHsm HSMs should not be degraded"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for clstr in describe_clusters(cache, session)["Clusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clstr,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = clstr["ClusterId"]
        for hsm in clstr['Hsms']:
            HsmId = hsm['HsmId']
            if hsm["State"] != "DEGRADED":
                #Passing Check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": HsmId + "/cloudhsm-cluster-degradation-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": HsmId,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[CloudHsm.2] CloudHsm HSMs should not be in a degraded state",
                    "Description": f"CloudHSM HSM {HsmId} is not in a degraded state",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on HSM Clusters refer to the AWS CloudHsm User Guide on managing Hsms",
                            "Url": "https://docs.aws.amazon.com/cloudhsm/latest/userguide/introduction.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Security Services",
                        "AssetService": "AWS CloudHSM",
                        "AssetComponent": "Hardware Security Module"
                    },
                    "Resources": [
                        {
                            "Type": "AwsCloudHsmHsm",
                            "Id": HsmId,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"AwsCloudHsmHsm": {"HsmId": HsmId}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST CSF V1.1 DE.AE-3",
                            "NIST CSF V1.1 DE.AE-5",
                            "NIST CSF V1.1 DE.CM-1",
                            "NIST CSF V1.1 DE.DP-2",                        
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 AU-12",
                            "NIST SP 800-53 Rev. 4 IR-5",
                            "NIST SP 800-53 Rev. 4 IR-6",
                            "AICPA TSC CC4.1",
                            "AICPA TSC CC5.1",
                            "ISO 27001:2013 A.10.1.2",
                            "ISO 27001:2013 A.12.4.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": HsmId + "/cloudhsm-cluster-degradation-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": HsmId,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[CloudHsm.2] CloudHsm HSMs should not be in a degraded state",
                    "Description": f"CloudHSM HSM {HsmId} is in a degraded state",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on HSM Clusters refer to the AWS CloudHsm User Guide on managing Hsms",
                            "Url": "https://docs.aws.amazon.com/cloudhsm/latest/userguide/introduction.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Security Services",
                        "AssetService": "AWS CloudHSM",
                        "AssetComponent": "Hardware Security Module"
                    },
                    "Resources": [
                        {
                            "Type": "AwsCloudHsmHsm",
                            "Id": HsmId,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"AwsCloudHsmHsm": {"HsmId": HsmId}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST CSF V1.1 DE.AE-3",
                            "NIST CSF V1.1 DE.AE-5",
                            "NIST CSF V1.1 DE.CM-1",
                            "NIST CSF V1.1 DE.DP-2",                        
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 AU-12",
                            "NIST SP 800-53 Rev. 4 IR-5",
                            "NIST SP 800-53 Rev. 4 IR-6",
                            "AICPA TSC CC4.1",
                            "AICPA TSC CC5.1",
                            "ISO 27001:2013 A.10.1.2",
                            "ISO 27001:2013 A.12.4.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding

@registry.register_check("cloudhsm")
def cloudhsm_cluster_backup_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudHsm.3] CloudHsm clusters should have at least 1 backup in a READY state"""
    cloudhsm = session.client("cloudhsmv2")
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for clstr in describe_clusters(cache, session)["Clusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clstr,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = clstr["ClusterId"]
        
        backups = cloudhsm.describe_backups(
            Filters = {
                'clusterIds': [clusterId]
            }
        )
        activeBackups = [x for x in backups['Backups'] if x['BackupState'] == 'READY']
        if len(activeBackups) > 0:
            #Passing Check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterId + "/cloudhsm-cluster-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudHsm.3] CloudHsm clusters should have at least 1 backup in a READY state",
                "Description": f"CloudHSM cluster {clusterId} has at least 1 backup in a READY state",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on HSM Clusters refer to the AWS CloudHsm User Guide on managing Backups",
                        "Url": "https://docs.aws.amazon.com/cloudhsm/latest/userguide/backups.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "AWS CloudHSM",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudHsmCluster",
                        "Id": clusterId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCloudHsmCluster": {"ClusterId": clusterId}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.AE-5",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.DP-2",                        
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-6",
                        "AICPA TSC CC4.1",
                        "AICPA TSC CC5.1",
                        "ISO 27001:2013 A.10.1.2",
                        "ISO 27001:2013 A.12.4.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterId + "/cloudhsm-cluster-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[CloudHsm.3] CloudHsm clusters should have at least 1 backup in a READY state",
                "Description": f"CloudHSM cluster {clusterId} does not have at least 1 backup in a READY state",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on HSM Clusters refer to the AWS CloudHsm User Guide on managing Backups",
                        "Url": "https://docs.aws.amazon.com/cloudhsm/latest/userguide/backups.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "AWS CloudHSM",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudHsmCluster",
                        "Id": clusterId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCloudHsmCluster": {"ClusterId": clusterId}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.AE-5",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.DP-2",                        
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-6",
                        "AICPA TSC CC4.1",
                        "AICPA TSC CC5.1",
                        "ISO 27001:2013 A.10.1.2",
                        "ISO 27001:2013 A.12.4.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding