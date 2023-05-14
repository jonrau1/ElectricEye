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

def describe_replication_instances(cache, session):
    dms = session.client("dms")
    response = cache.get("describe_replication_instances")
    if response:
        return response
    cache["describe_replication_instances"] = dms.describe_replication_instances()
    return cache["describe_replication_instances"]

@registry.register_check("dms")
def dms_replication_instance_public_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DMS.1] Database Migration Service instances should not be publicly accessible"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for ri in describe_replication_instances(cache, session)["ReplicationInstances"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(ri,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        dmsInstanceId = ri["ReplicationInstanceIdentifier"]
        dmsInstanceArn = ri["ReplicationInstanceArn"]
        # this is a failing check
        if ri["PubliclyAccessible"] == True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{dmsInstanceArn}/dms-replication-instance-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": dmsInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[DMS.1] Database Migration Service instances should not be publicly accessible",
                "Description": f"Database Migration Service instance {dmsInstanceId} is publicly accessible. A private replication instance has a private IP address that you can't access outside the replication network. You use a private instance when both source and target databases are in the same network that is connected to the replication instance's VPC. The network can be connected to the VPC by using a VPN, AWS Direct Connect, or VPC peering. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Public access on DMS instances cannot be changed, however, you can change the subnets that are in the subnet group that is associated with the replication instance to private subnets. For more informaton see the AWS Premium Support post How can I disable public access for an AWS DMS replication instance?",
                        "Url": "https://aws.amazon.com/premiumsupport/knowledge-center/dms-disable-public-access/",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Migration & Transfer",
                    "AssetService": "AWS Database Migration Service",
                    "AssetComponent": "Replication Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsDmsReplicationInstance",
                        "Id": dmsInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ReplicationInstanceIdentifier": dmsInstanceId
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
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{dmsInstanceArn}/dms-replication-instance-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": dmsInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DMS.1] Database Migration Service instances should not be publicly accessible",
                "Description": f"Database Migration Service instance {dmsInstanceId} is not publicly accessible.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Public access on DMS instances cannot be changed, however, you can change the subnets that are in the subnet group that is associated with the replication instance to private subnets. For more informaton see the AWS Premium Support post How can I disable public access for an AWS DMS replication instance?",
                        "Url": "https://aws.amazon.com/premiumsupport/knowledge-center/dms-disable-public-access/",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Migration & Transfer",
                    "AssetService": "AWS Database Migration Service",
                    "AssetComponent": "Replication Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsDmsReplicationInstance",
                        "Id": dmsInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ReplicationInstanceIdentifier": dmsInstanceId
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

@registry.register_check("dms")
def dms_replication_instance_multi_az_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DMS.2] Database Migration Service instances should have Multi-AZ configured"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for ri in describe_replication_instances(cache, session)["ReplicationInstances"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(ri,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        dmsInstanceId = ri["ReplicationInstanceIdentifier"]
        dmsInstanceArn = ri["ReplicationInstanceArn"]
        # this is a failing check
        if ri["MultiAZ"] == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{dmsInstanceArn}/dms-replication-instance-multi-az-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": dmsInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[DMS.2] Database Migration Service instances should have Multi-AZ configured",
                "Description": f"Database Migration Service instance {dmsInstanceId} does not have Multi-AZ configured. Choosing a Multi-AZ instance can protect your migration from storage failures. Most migrations are transient and aren't intended to run for long periods of time. If you use AWS DMS for ongoing replication purposes, choosing a Multi-AZ instance can improve your availability should a storage issue occur. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on when to configure DMS instances for Multi-AZ refer to the Improving the performance of an AWS DMS migration subsection of the Best pratices section of the AWS Database Migration Service User Guide.",
                        "Url": "https://docs.aws.amazon.com/dms/latest/userguide/CHAP_BestPractices.html#CHAP_BestPractices.Performance",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Migration & Transfer",
                    "AssetService": "AWS Database Migration Service",
                    "AssetComponent": "Replication Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsDmsReplicationInstance",
                        "Id": dmsInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ReplicationInstanceIdentifier": dmsInstanceId
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
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{dmsInstanceArn}/dms-replication-instance-multi-az-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": dmsInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DMS.2] Database Migration Service instances should have Multi-AZ configured",
                "Description": f"Database Migration Service instance {dmsInstanceId} has Multi-AZ configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on when to configure DMS instances for Multi-AZ refer to the Improving the performance of an AWS DMS migration subsection of the Best pratices section of the AWS Database Migration Service User Guide.",
                        "Url": "https://docs.aws.amazon.com/dms/latest/userguide/CHAP_BestPractices.html#CHAP_BestPractices.Performance",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Migration & Transfer",
                    "AssetService": "AWS Database Migration Service",
                    "AssetComponent": "Replication Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsDmsReplicationInstance",
                        "Id": dmsInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ReplicationInstanceIdentifier": dmsInstanceId
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

@registry.register_check("dms")
def dms_replication_instance_minor_version_update_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DMS.3] Database Migration Service instances should be configured to have minor version updates be automatically applied"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for ri in describe_replication_instances(cache, session)["ReplicationInstances"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(ri,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        dmsInstanceId = ri["ReplicationInstanceIdentifier"]
        dmsInstanceArn = ri["ReplicationInstanceArn"]
        # this is a failing check
        if ri["AutoMinorVersionUpgrade"] == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{dmsInstanceArn}/dms-replication-instance-minor-version-auto-update-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": dmsInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[DMS.3] Database Migration Service instances should be configured to have minor version updates automatically applied",
                "Description": f"Database Migration Service instance {dmsInstanceId} is not configured to have minor version updates automatically applied. AWS periodically releases new versions of the AWS DMS replication engine software, with new features and performance improvements. Each version of the replication engine software has its own version number. It's critical to test the existing version of your AWS DMS replication instance running a production work load before you upgrade your replication instance to a later version. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring DMS instances for minor version updates refer to the Upgrading a replication instance version subsection of the Best practices section of the AWS Database Migration Service User Guide.",
                        "Url": "https://docs.aws.amazon.com/dms/latest/userguide/CHAP_BestPractices.html#CHAP_BestPractices.RIUpgrade",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Migration & Transfer",
                    "AssetService": "AWS Database Migration Service",
                    "AssetComponent": "Replication Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsDmsReplicationInstance",
                        "Id": dmsInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ReplicationInstanceIdentifier": dmsInstanceId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
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
                "Id": f"{dmsInstanceArn}/dms-replication-instance-minor-version-auto-update-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": dmsInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DMS.3] Database Migration Service instances should be configured to have minor version updates automatically applied",
                "Description": f"Database Migration Service instance {dmsInstanceId} is configured to have minor version updates automatically applied.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring DMS instances for minor version updates refer to the Upgrading a replication instance version subsection of the Best practices section of the AWS Database Migration Service User Guide.",
                        "Url": "https://docs.aws.amazon.com/dms/latest/userguide/CHAP_BestPractices.html#CHAP_BestPractices.RIUpgrade",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Migration & Transfer",
                    "AssetService": "AWS Database Migration Service",
                    "AssetComponent": "Replication Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsDmsReplicationInstance",
                        "Id": dmsInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ReplicationInstanceIdentifier": dmsInstanceId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding