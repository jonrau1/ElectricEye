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

def get_owned_ssm_docs(cache, session):
    ssm = session.client("ssm")
    ssmDocs = []
    response = cache.get("get_owned_ssm_docs")
    if response:
        return response
    paginator = ssm.get_paginator("list_documents")
    if paginator:
        for page in paginator.paginate(Filters=[{"Key": "Owner","Values": ["Self"]}]):
            for doc in page["DocumentIdentifiers"]:
                ssmDocs.append(doc)
        cache["get_owned_ssm_docs"] = ssmDocs
        return cache["get_owned_ssm_docs"]

def list_associations(cache, session):
    ssm = session.client("ssm")
    ssmAssocs = []
    response = cache.get("list_associations")
    if response:
        return response
    paginator = ssm.get_paginator("list_associations")
    if paginator:
        for page in paginator.paginate():
            for assoc in page["Associations"]:
                ssmAssocs.append(assoc)
        cache["list_associations"] = ssmAssocs
        return cache["list_associations"]

def describe_instances(cache, session):
    ec2 = session.client("ec2")
    instanceList = []
    response = cache.get("describe_instances")
    if response:
        return response
    paginator = ec2.get_paginator("describe_instances")
    if paginator:
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name","Values": ["running","stopped"]}]):
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    instanceList.append(i)
        cache["describe_instances"] = instanceList
        return cache["describe_instances"]

@registry.register_check("ssm")
def ssm_self_owned_document_public_share_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SSM.1] Self-owned SSM Documents should not be publicly shared"""
    ssm = session.client("ssm")
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for doc in get_owned_ssm_docs(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(doc,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        docName = doc["Name"]
        docArn = f"arn:{awsPartition}:ssm:{awsRegion}:{awsAccountId}:document/{docName}"
        docType = doc["DocumentType"]
        # Check if "all" is specified for shared Accounts, this means the Document is public
        docShare = ssm.describe_document_permission(Name=docName,PermissionType="Share")["AccountIds"]
        if "all" in docShare:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docArn}/self-owned-ssm-doc-public-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[SSM.1] Self-owned SSM Documents should not be publicly shared",
                "Description": f"AWS Systems Manager Document {docName} is publicly shared. SSM Documents may contain direct or indirect references to sensitive values and business logic and should only be shared with AWS Accounts who have a 'need to know'. If this configuration is not intended refer to the remediation instructions.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on sharing SSM Doucments refer to the Share an SSM document section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-how-to-share.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "AWS Systems Manager",
                    "AssetComponent": "Document"
                },
                "Resources": [
                    {
                        "Type": "AwsSsmDocument",
                        "Id": docArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": docName,
                                "DocumentType": docType
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docArn}/self-owned-ssm-doc-public-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docArn,
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
                "Title": "[SSM.1] Self-owned SSM Documents should not be publicly shared",
                "Description": f"AWS Systems Manager Document {docName} is not publicly shared.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on sharing SSM Doucments refer to the Share an SSM document section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-how-to-share.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "AWS Systems Manager",
                    "AssetComponent": "Document"
                },
                "Resources": [
                    {
                        "Type": "AwsSsmDocument",
                        "Id": docArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": docName,
                                "DocumentType": docType
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

@registry.register_check("ssm")
def ssm_update_ssm_agent_association_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SSM.2] AWS State Manager should be used to update SSM Agents for all EC2 instances in your Region"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if len(describe_instances(cache, session)) == 0:
        pass
    else:
        # create a list to hold all of the SSM Documents that are referenced by SSM Associations
        # if we do not find a match we will fail this check
        assocDocNames = [x["Name"] for x in list_associations(cache, session)]
        if "AWS-UpdateSSMAgent" not in assocDocNames:
            # B64 encode all of the details for the Asset
            assetB64 = None
            # this is a failing check - a State Mgr Association for the "AWS-UpdateSSMAgent" Doc doesn't exist
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{awsAccountId}/{awsRegion}/ssm-state-mgr-ssm-agent-update-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{awsAccountId}/{awsRegion}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SSM.2] AWS State Manager should be used to update SSM Agents for all EC2 instances in your Region",
                "Description": f"AWS Account {awsAccountId} for AWS Region {awsRegion} does not have a State Manager Association to update SSM Agents for EC2. Ensuring that you keep the SSM up-to-date with automation ensures that all latest SSM features such as vulnerability and patch management will be available to your instances. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SSM State Manager best practices refer to the Use cases and best practices section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-best-practices.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "AWS Systems Manager",
                    "AssetComponent": "Association"
                },
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/AWS_State_Manager_UpdateSSMAgent_Check",
                        "Partition": awsPartition,
                        "Region": awsRegion
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
            # carry out the logic
            for assoc in list_associations(cache, session):
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(assoc,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                # we have established we have a matching association with this Document so we can skip all others
                if assoc["Name"] != "AWS-UpdateSSMAgent":
                    continue
                else:
                    assocName = assoc["AssociationName"]
                    assocId = assoc["AssociationId"]
                    associationArn = f"arn:{awsPartition}:ssm:{awsRegion}:{awsAccountId}:association/{assocId}"
                    assocTargets = assoc["Targets"]
                    # determine the targets
                    for t in assocTargets:
                        if t["Key"] != "InstanceIds":
                            continue
                        else:
                            if "*" not in t["Values"]:
                                # this is a failing check
                                finding = {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": f"{awsAccountId}/{awsRegion}/ssm-state-mgr-ssm-agent-update-check",
                                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                    "GeneratorId": f"{awsAccountId}/{awsRegion}",
                                    "AwsAccountId": awsAccountId,
                                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "LOW"},
                                    "Confidence": 99,
                                    "Title": "[SSM.2] AWS State Manager should be used to update SSM Agents for all EC2 instances in your Region",
                                    "Description": f"AWS Account {awsAccountId} for AWS Region {awsRegion} has a State Manager Association to update SSM Agents for EC2 called {assocName}, but is not set to target all current and future Instances. Ensuring that you keep the SSM up-to-date with automation ensures that all latest SSM features such as vulnerability and patch management will be available to your instances. Refer to the remediation instructions if this configuration is not intended.",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on SSM State Manager best practices refer to the Use cases and best practices section of the AWS Systems Manager User Guide",
                                            "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-best-practices.html"
                                        }
                                    },
                                    "ProductFields": {
                                        "ProductName": "ElectricEye",
                                        "Provider": "AWS",
                                        "ProviderType": "CSP",
                                        "ProviderAccountId": awsAccountId,
                                        "AssetRegion": awsRegion,
                                        "AssetDetails": assetB64,
                                        "AssetClass": "Management & Governance",
                                        "AssetService": "AWS Systems Manager",
                                        "AssetComponent": "Association"
                                    },
                                    "Resources": [
                                        {
                                            "Type": "AwsSsmAssociation",
                                            "Id": associationArn,
                                            "Partition": awsPartition,
                                            "Region": awsRegion
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
                                # this is a passing check
                                finding = {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": f"{awsAccountId}/{awsRegion}/ssm-state-mgr-ssm-agent-update-check",
                                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                    "GeneratorId": f"{awsAccountId}/{awsRegion}",
                                    "AwsAccountId": awsAccountId,
                                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "INFORMATIONAL"},
                                    "Confidence": 99,
                                    "Title": "[SSM.2] AWS State Manager should be used to update SSM Agents for all EC2 instances in your Region",
                                    "Description": f"AWS Account {awsAccountId} for AWS Region {awsRegion} has a State Manager Association to update SSM Agents for EC2 that targets all instances.",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on SSM State Manager best practices refer to the Use cases and best practices section of the AWS Systems Manager User Guide",
                                            "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-best-practices.html"
                                        }
                                    },
                                    "ProductFields": {
                                        "ProductName": "ElectricEye",
                                        "Provider": "AWS",
                                        "ProviderType": "CSP",
                                        "ProviderAccountId": awsAccountId,
                                        "AssetRegion": awsRegion,
                                        "AssetDetails": assetB64,
                                        "AssetClass": "Management & Governance",
                                        "AssetService": "AWS Systems Manager",
                                        "AssetComponent": "Association"
                                    },
                                    "Resources": [
                                        {
                                            "Type": "AwsSsmAssociation",
                                            "Id": associationArn,
                                            "Partition": awsPartition,
                                            "Region": awsRegion
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

@registry.register_check("ssm")
def ssm_patch_instances_association_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SSM.3] AWS State Manager should be used to patch all EC2 instances in your Region"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if len(describe_instances(cache, session)) == 0:
        pass
    else:
        # create a list to hold all of the SSM Documents that are referenced by SSM Associations
        # if we do not find a match we will fail this check
        assocDocNames = [x["Name"] for x in list_associations(cache, session)]
        # B64 encode all of the details for the Asset
        if "AWS-RunPatchBaseline" not in assocDocNames:
            assetB64 = None
            # this is a failing check - a State Mgr Association for the "AWS-RunPatchBaseline" Doc doesn't exist
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{awsAccountId}/{awsRegion}/ssm-state-mgr-patch-manager-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{awsAccountId}/{awsRegion}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SSM.3] AWS State Manager should be used to patch all EC2 instances in your Region",
                "Description": f"AWS Account {awsAccountId} for AWS Region {awsRegion} does not have a State Manager Association to patch EC2 instances. Ensuring that you are automatically applying security patches to your instances can help to avoid exploitations against your environment and lower you outstanding vulnerability counts. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SSM State Manager best practices refer to the Use cases and best practices section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-best-practices.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "AWS Systems Manager",
                    "AssetComponent": "Association"
                },
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/AWS_State_Manager_RunPatchBaseline_Check",
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # carry out the logic
            for assoc in list_associations(cache, session):
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(assoc,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                # we have established we have a matching association with this Document so we can skip all others
                if assoc["Name"] != "AWS-RunPatchBaseline":
                    continue
                else:
                    assocName = assoc["AssociationName"]
                    assocId = assoc["AssociationId"]
                    associationArn = f"arn:{awsPartition}:ssm:{awsRegion}:{awsAccountId}:association/{assocId}"
                    assocTargets = assoc["Targets"]
                    # determine the targets
                    for t in assocTargets:
                        if t["Key"] != "InstanceIds":
                            continue
                        else:
                            if "*" not in t["Values"]:
                                # this is a failing check
                                finding = {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": f"{awsAccountId}/{awsRegion}/ssm-state-mgr-patch-manager-check",
                                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                    "GeneratorId": f"{awsAccountId}/{awsRegion}",
                                    "AwsAccountId": awsAccountId,
                                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "LOW"},
                                    "Confidence": 99,
                                    "Title": "[SSM.3] AWS State Manager should be used to patch all EC2 instances in your Region",
                                    "Description": f"AWS Account {awsAccountId} for AWS Region {awsRegion} has a State Manager Association to patch EC2 instances called {assocName}, but is not set to target all current and future Instances. Ensuring that you are automatically applying security patches to your instances can help to avoid exploitations against your environment and lower you outstanding vulnerability counts. Refer to the remediation instructions if this configuration is not intended.",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on SSM State Manager best practices refer to the Use cases and best practices section of the AWS Systems Manager User Guide",
                                            "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-best-practices.html"
                                        }
                                    },
                                    "ProductFields": {
                                        "ProductName": "ElectricEye",
                                        "Provider": "AWS",
                                        "ProviderType": "CSP",
                                        "ProviderAccountId": awsAccountId,
                                        "AssetRegion": awsRegion,
                                        "AssetDetails": assetB64,
                                        "AssetClass": "Management & Governance",
                                        "AssetService": "AWS Systems Manager",
                                        "AssetComponent": "Association"
                                    },
                                    "Resources": [
                                        {
                                            "Type": "AwsAccount",
                                            "Id": associationArn,
                                            "Partition": awsPartition,
                                            "Region": awsRegion
                                        }
                                    ],
                                    "Compliance": {
                                        "Status": "FAILED",
                                        "RelatedRequirements": [
                                            "NIST CSF V1.1 ID.AM-2",
                                            "NIST SP 800-53 Rev. 4 CM-8",
                                            "NIST SP 800-53 Rev. 4 PM-5",
                                            "AICPA TSC CC3.2",
                                            "AICPA TSC CC6.1",
                                            "ISO 27001:2013 A.8.1.1",
                                            "ISO 27001:2013 A.8.1.2",
                                            "ISO 27001:2013 A.12.5.1"
                                        ]
                                    },
                                    "Workflow": {"Status": "NEW"},
                                    "RecordState": "ACTIVE"
                                }
                                yield finding
                            else:
                                # this is a passing check
                                finding = {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": f"{awsAccountId}/{awsRegion}/ssm-state-mgr-patch-manager-check",
                                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                    "GeneratorId": f"{awsAccountId}/{awsRegion}",
                                    "AwsAccountId": awsAccountId,
                                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "INFORMATIONAL"},
                                    "Confidence": 99,
                                    "Title": "[SSM.3] AWS State Manager should be used to patch all EC2 instances in your Region",
                                    "Description": f"AWS Account {awsAccountId} for AWS Region {awsRegion} has a State Manager Association to patch EC2 instances that targets all instances.",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on SSM State Manager best practices refer to the Use cases and best practices section of the AWS Systems Manager User Guide",
                                            "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-best-practices.html"
                                        }
                                    },
                                    "ProductFields": {
                                        "ProductName": "ElectricEye",
                                        "Provider": "AWS",
                                        "ProviderType": "CSP",
                                        "ProviderAccountId": awsAccountId,
                                        "AssetRegion": awsRegion,
                                        "AssetDetails": assetB64,
                                        "AssetClass": "Management & Governance",
                                        "AssetService": "AWS Systems Manager",
                                        "AssetComponent": "Association"
                                    },
                                    "Resources": [
                                        {
                                            "Type": "AwsAccount",
                                            "Id": associationArn,
                                            "Partition": awsPartition,
                                            "Region": awsRegion
                                        }
                                    ],
                                    "Compliance": {
                                        "Status": "PASSED",
                                        "RelatedRequirements": [
                                            "NIST CSF V1.1 ID.AM-2",
                                            "NIST SP 800-53 Rev. 4 CM-8",
                                            "NIST SP 800-53 Rev. 4 PM-5",
                                            "AICPA TSC CC3.2",
                                            "AICPA TSC CC6.1",
                                            "ISO 27001:2013 A.8.1.1",
                                            "ISO 27001:2013 A.8.1.2",
                                            "ISO 27001:2013 A.12.5.1"
                                        ]
                                    },
                                    "Workflow": {"Status": "RESOLVED"},
                                    "RecordState": "ARCHIVED"
                                }
                                yield finding

@registry.register_check("ssm")
def ssm_gather_software_inventory_association_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SSM.4] AWS State Manager should be used to gather software inventory data from all EC2 instances in your Region"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if len(describe_instances(cache, session)) == 0:
        pass
    else:
        # create a list to hold all of the SSM Documents that are referenced by SSM Associations
        # if we do not find a match we will fail this check
        assocDocNames = [x["Name"] for x in list_associations(cache, session)]
        if "AWS-GatherSoftwareInventory" not in assocDocNames:
            assetB64 = None
            # this is a failing check - a State Mgr Association for the "AWS-GatherSoftwareInventory" Doc doesn't exist
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{awsAccountId}/{awsRegion}/ssm-state-mgr-gather-sware-inventory-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{awsAccountId}/{awsRegion}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SSM.4] AWS State Manager should be used to gather software inventory data from all EC2 instances in your Region",
                "Description": f"AWS Account {awsAccountId} for AWS Region {awsRegion} does not have a State Manager Association to gather software inventory from EC2 instances. Ensuring that you are automatically gathering software inventory can be used to managed vulnerable and potentially unwanted software and configurations. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SSM State Manager best practices refer to the Use cases and best practices section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-best-practices.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "AWS Systems Manager",
                    "AssetComponent": "Association"
                },
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/AWS_State_Manager_GatherSoftwareInventory_Check",
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # carry out the logic
            for assoc in list_associations(cache, session):
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(assoc,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                # we have established we have a matching association with this Document so we can skip all others
                if assoc["Name"] != "AWS-GatherSoftwareInventory":
                    continue
                else:
                    assocName = assoc["AssociationName"]
                    assocId = assoc["AssociationId"]
                    associationArn = f"arn:{awsPartition}:ssm:{awsRegion}:{awsAccountId}:association/{assocId}"
                    assocTargets = assoc["Targets"]
                    # determine the targets
                    for t in assocTargets:
                        if t["Key"] != "InstanceIds":
                            continue
                        else:
                            if "*" not in t["Values"]:
                                # this is a failing check
                                finding = {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": f"{awsAccountId}/{awsRegion}/ssm-state-mgr-gather-sware-inventory-check",
                                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                    "GeneratorId": f"{awsAccountId}/{awsRegion}",
                                    "AwsAccountId": awsAccountId,
                                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "LOW"},
                                    "Confidence": 99,
                                    "Title": "[SSM.4] AWS State Manager should be used to gather software inventory data from all EC2 instances in your Region",
                                    "Description": f"AWS Account {awsAccountId} for AWS Region {awsRegion} has a State Manager Association to gather software inventory from EC2 instances called {assocName}, but is not set to target all current and future Instances. Ensuring that you are automatically gathering software inventory can be used to managed vulnerable and potentially unwanted software and configurations. Refer to the remediation instructions if this configuration is not intended.",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on SSM State Manager best practices refer to the Use cases and best practices section of the AWS Systems Manager User Guide",
                                            "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-best-practices.html"
                                        }
                                    },
                                    "ProductFields": {
                                        "ProductName": "ElectricEye",
                                        "Provider": "AWS",
                                        "ProviderType": "CSP",
                                        "ProviderAccountId": awsAccountId,
                                        "AssetRegion": awsRegion,
                                        "AssetDetails": assetB64,
                                        "AssetClass": "Management & Governance",
                                        "AssetService": "AWS Systems Manager",
                                        "AssetComponent": "Association"
                                    },
                                    "Resources": [
                                        {
                                            "Type": "AwsAccount",
                                            "Id": associationArn,
                                            "Partition": awsPartition,
                                            "Region": awsRegion
                                        }
                                    ],
                                    "Compliance": {
                                        "Status": "FAILED",
                                        "RelatedRequirements": [
                                            "NIST CSF V1.1 ID.AM-2",
                                            "NIST SP 800-53 Rev. 4 CM-8",
                                            "NIST SP 800-53 Rev. 4 PM-5",
                                            "AICPA TSC CC3.2",
                                            "AICPA TSC CC6.1",
                                            "ISO 27001:2013 A.8.1.1",
                                            "ISO 27001:2013 A.8.1.2",
                                            "ISO 27001:2013 A.12.5.1"
                                        ]
                                    },
                                    "Workflow": {"Status": "NEW"},
                                    "RecordState": "ACTIVE"
                                }
                                yield finding
                            else:
                                # this is a passing check
                                finding = {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": f"{awsAccountId}/{awsRegion}/ssm-state-mgr-gather-sware-inventory-check",
                                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                    "GeneratorId": f"{awsAccountId}/{awsRegion}",
                                    "AwsAccountId": awsAccountId,
                                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "INFORMATIONAL"},
                                    "Confidence": 99,
                                    "Title": "[SSM.4] AWS State Manager should be used to gather software inventory data from all EC2 instances in your Region",
                                    "Description": f"AWS Account {awsAccountId} for AWS Region {awsRegion} has a State Manager Association to gather software inventory from EC2 instances that targets all instances.",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on SSM State Manager best practices refer to the Use cases and best practices section of the AWS Systems Manager User Guide",
                                            "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-best-practices.html"
                                        }
                                    },
                                    "ProductFields": {
                                        "ProductName": "ElectricEye",
                                        "Provider": "AWS",
                                        "ProviderType": "CSP",
                                        "ProviderAccountId": awsAccountId,
                                        "AssetRegion": awsRegion,
                                        "AssetDetails": assetB64,
                                        "AssetClass": "Management & Governance",
                                        "AssetService": "AWS Systems Manager",
                                        "AssetComponent": "Association"
                                    },
                                    "Resources": [
                                        {
                                            "Type": "AwsAccount",
                                            "Id": associationArn,
                                            "Partition": awsPartition,
                                            "Region": awsRegion
                                        }
                                    ],
                                    "Compliance": {
                                        "Status": "PASSED",
                                        "RelatedRequirements": [
                                            "NIST CSF V1.1 ID.AM-2",
                                            "NIST SP 800-53 Rev. 4 CM-8",
                                            "NIST SP 800-53 Rev. 4 PM-5",
                                            "AICPA TSC CC3.2",
                                            "AICPA TSC CC6.1",
                                            "ISO 27001:2013 A.8.1.1",
                                            "ISO 27001:2013 A.8.1.2",
                                            "ISO 27001:2013 A.12.5.1"
                                        ]
                                    },
                                    "Workflow": {"Status": "RESOLVED"},
                                    "RecordState": "ARCHIVED"
                                }
                                yield finding