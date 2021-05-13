# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

import boto3
import datetime
import json
import os
from check_register import CheckRegister

registry = CheckRegister()
cloudhsm = boto3.client("cloudhsmv2")

def describe_clusters(cache):
    response = cache.get("describe_clusters")
    if response:
        return response
    cache["describe_clusters"] = cloudhsm.describe_clusters()
    return cache["describe_clusters"]


@registry.register_check("cloudhsm")
def cloudhsm_cluster_degradation_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudHsm.1] CloudHsm clusters should not be degraded"""
    hsm_clusters = describe_clusters(cache=cache)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for clstr in hsm_clusters["Clusters"]:
        ClusterId = clstr["ClusterId"]
        if clstr["State"] != "DEGRADED":
            #Passing Check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": ClusterId + "/cloudhsm-cluster-degradation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": ClusterId,
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
                "Description": f"CloudHSM cluster {ClusterId} is not in a degraded state",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on HSM Clusters refer to the AWS CloudHsm User Guide on managing cloudhsm clusters",
                        "Url": "https://docs.aws.amazon.com/cloudhsm/latest/userguide/manage-clusters.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudHsmCluster",
                        "Id": ClusterId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCloudHsmCluster": {"ClusterId": ClusterId}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-2",
                        "NIST CSF DE.AE-3",
                        "NIST CSF DE.AE-5",
                        "NIST CSF DE.CM-1",
                        "NIST CSF DE.DP-2",                        
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-6",
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
                "Id": ClusterId + "/cloudhsm-cluster-degradation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": ClusterId,
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
                "Description": f"CloudHSM cluster {ClusterId} is in a degraded state",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on HSM Clusters refer to the AWS CloudHsm User Guide on managing cloudhsm clusters",
                        "Url": "https://docs.aws.amazon.com/cloudhsm/latest/userguide/manage-clusters.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudHsmCluster",
                        "Id": ClusterId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCloudHsmCluster": {"ClusterId": ClusterId}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-2",
                        "NIST CSF DE.AE-3",
                        "NIST CSF DE.AE-5",
                        "NIST CSF DE.CM-1",
                        "NIST CSF DE.DP-2",                        
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-6",
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
def cloudhsm_hsm_degradation_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudHsm.2] CloudHsm HSMs should not be degraded"""
    hsm_clusters = describe_clusters(cache=cache)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for clstr in hsm_clusters["Clusters"]:
        ClusterId = clstr["ClusterId"]
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
                    "ProductFields": {"Product Name": "ElectricEye"},
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
                            "NIST CSF DE.AE-2",
                            "NIST CSF DE.AE-3",
                            "NIST CSF DE.AE-5",
                            "NIST CSF DE.CM-1",
                            "NIST CSF DE.DP-2",                        
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 AU-12",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-6",
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
                    "ProductFields": {"Product Name": "ElectricEye"},
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
                            "NIST CSF DE.AE-2",
                            "NIST CSF DE.AE-3",
                            "NIST CSF DE.AE-5",
                            "NIST CSF DE.CM-1",
                            "NIST CSF DE.DP-2",                        
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 AU-12",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-6",
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
def cloudhsm_cluster_backup_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudHsm.3] CloudHsm clusters should have at least 1 backup in a READY state"""
    hsm_clusters = describe_clusters(cache=cache)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for clstr in hsm_clusters["Clusters"]:
        ClusterId = clstr["ClusterId"]
        
        backups = cloudhsm.describe_backups(
            Filters = {
                'clusterIds': [ClusterId]
            }
        )
        activeBackups = [x for x in backups['Backups'] if x['BackupState'] == 'READY']
        if len(activeBackups) > 0:
            #Passing Check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": ClusterId + "/cloudhsm-cluster-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": ClusterId,
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
                "Description": f"CloudHSM cluster {ClusterId} has at least 1 backup in a READY state",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on HSM Clusters refer to the AWS CloudHsm User Guide on managing Backups",
                        "Url": "https://docs.aws.amazon.com/cloudhsm/latest/userguide/backups.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudHsmCluster",
                        "Id": ClusterId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCloudHsmCluster": {"ClusterId": ClusterId}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-2",
                        "NIST CSF DE.AE-3",
                        "NIST CSF DE.AE-5",
                        "NIST CSF DE.CM-1",
                        "NIST CSF DE.DP-2",                        
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-6",
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
                "Id": ClusterId + "/cloudhsm-cluster-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": ClusterId,
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
                "Description": f"CloudHSM cluster {ClusterId} does not have at least 1 backup in a READY state",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on HSM Clusters refer to the AWS CloudHsm User Guide on managing Backups",
                        "Url": "https://docs.aws.amazon.com/cloudhsm/latest/userguide/backups.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudHsmCluster",
                        "Id": ClusterId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCloudHsmCluster": {"ClusterId": ClusterId}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-2",
                        "NIST CSF DE.AE-3",
                        "NIST CSF DE.AE-5",
                        "NIST CSF DE.CM-1",
                        "NIST CSF DE.DP-2",                        
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-6",
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