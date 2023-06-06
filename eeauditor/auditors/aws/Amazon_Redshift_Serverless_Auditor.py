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

def list_redshift_serverless_namespaces(cache, session):
    rserverless = session.client("redshift-serverless")

    response = cache.get("list_redshift_serverless_namespaces")
    if response:
        return response
    
    cache["list_redshift_serverless_namespaces"] = rserverless.list_namespaces()["namespaces"]
    return cache["list_redshift_serverless_namespaces"]

def list_redshift_serverless_workgroups(cache, session):
    rserverless = session.client("redshift-serverless")

    response = cache.get("list_redshift_serverless_workgroups")
    if response:
        return response
    
    cache["list_redshift_serverless_workgroups"] = rserverless.list_workgroups()["workgroups"]
    return cache["list_redshift_serverless_workgroups"]

@registry.register_check("redshift-serverless")
def redshift_serverless_namespace_iam_role_association_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift-Serverless.1] Redshift Serverless namespaces should have IAM Roles associated to enable access to other AWS services"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for namespace in list_redshift_serverless_namespaces(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(namespace,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        namespaceName = namespace["namespaceName"]
        namspaceArn = namespace["namespaceArn"]
        # this is a failing check - no roles assigned
        if not namespace["iamRoles"]:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{namspaceArn}/redshift-serverless-namespace-iam-role-association-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": namspaceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.1] Redshift Serverless namespaces should have IAM Roles associated to enable access to other AWS services",
                "Description": f"Redshift Serverless namespace {namespaceName} does not have any IAM Roles associated to enable access to other AWS service. Some Amazon Redshift features require Amazon Redshift to access other AWS services on your behalf. For your Amazon Redshift Serverless instance to act for you, supply security credentials to it. The preferred method to supply security credentials is to specify an AWS Identity and Access Management (IAM) role. When you use Amazon Redshift Serverless, you can associate multiple IAM roles with your namespace. This makes it easier to structure your permissions appropriately for a collection of database objects, so roles can perform actions on both internal and external data. For example, so you can run a COPY command in an Amazon Redshift database to retrieve data from Amazon S3 and populate a Redshift table. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift Serverless IAM Roles refer to the Security and connections in Amazon Redshift Serverless section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-security.html?icmpid=docs_console_unmapped"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Namespace"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessNamespace",
                        "Id": namspaceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "NamespaceName": namespaceName
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-6",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 PE-2",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{namspaceArn}/redshift-serverless-namespace-iam-role-association-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": namspaceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.1] Redshift Serverless namespaces should have IAM Roles associated to enable access to other AWS services",
                "Description": f"Redshift Serverless namespace {namespaceName} has IAM Roles associated to enable access to other AWS service.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift Serverless IAM Roles refer to the Security and connections in Amazon Redshift Serverless section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-security.html?icmpid=docs_console_unmapped"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Namespace"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessNamespace",
                        "Id": namspaceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "NamespaceName": namespaceName
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-6",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 PE-2",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("redshift-serverless")
def redshift_serverless_namespace_audit_log_export_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift-Serverless.2] Redshift Serverless namespaces should export all three audit log types"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for namespace in list_redshift_serverless_namespaces(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(namespace,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        namespaceName = namespace["namespaceName"]
        namspaceArn = namespace["namespaceArn"]
        # an empty export object or failing to have all three logs exported results in a failing check
        if not namespace["logExports"]:
            logExportPassing = False
        elif not all(x in namespace["logExports"] for x in ["useractivitylog", "userlog", "connectionlog"]):
            logExportPassing = False
        else:
            logExportPassing = True

        if logExportPassing is False:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{namspaceArn}/redshift-serverless-namespace-audit-log-export-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": namspaceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.2] Redshift Serverless namespaces should export all three audit log types",
                "Description": f"Redshift Serverless namespace {namespaceName} does not export all three audit log types. Amazon Redshift logs information in the following log files: 'Connection log' for authentication attempts, connections, and disconnections, 'User log' information about changes to database user definitions and 'User activity log' logs each query before it's run on the database. The connection and user logs are useful primarily for security purposes. You can use the connection log to monitor information about users connecting to the database and related connection information. This information might be their IP address, when they made the request, what type of authentication they used, and so on. You can use the user log to monitor changes to the definitions of database users. The user activity log is useful primarily for troubleshooting purposes. It tracks information about the types of queries that both the users and the system perform in the database. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift activity and connection logging refer to the Audit logging for Amazon Redshift Serverless section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-audit-logging.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Namespace"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessNamespace",
                        "Id": namspaceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "NamespaceName": namespaceName
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{namspaceArn}/redshift-serverless-namespace-audit-log-export-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": namspaceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.2] Redshift Serverless namespaces should exportall three audit log types",
                "Description": f"Redshift Serverless namespace {namespaceName} does export all three audit log types.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift activity and connection logging refer to the Audit logging for Amazon Redshift Serverless section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-audit-logging.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Namespace"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessNamespace",
                        "Id": namspaceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "NamespaceName": namespaceName
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("redshift-serverless")
def redshift_serverless_namespace_kms_cmk_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift-Serverless.3] Redshift Serverless namespaces should use a Customer Managed Key (CMK) for encryption"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for namespace in list_redshift_serverless_namespaces(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(namespace,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        namespaceName = namespace["namespaceName"]
        namspaceArn = namespace["namespaceArn"]
        if namespace["kmsKeyId"] == "AWS_OWNED_KMS_KEY":
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{namspaceArn}/redshift-serverless-namespace-kms-cmk-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": namspaceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.3] Redshift Serverless namespaces should use a Customer Managed Key (CMK) for encryption",
                "Description": f"Redshift Serverless namespace {namespaceName} does not use a Customer Managed Key (CMK) for encryption. In Amazon Redshift, encryption protects data at rest. Amazon Redshift Serverless uses AWS KMS key encryption automatically to encrypt both your Amazon Redshift Serverless resources and snapshots. As a best practice, most organizations review the type of data they store and have a plan to rotate encryption keys on a schedule. The frequency for rotating keys can vary, depending on your policies for data security. Amazon Redshift Serverless supports changing the AWS KMS key for the namespace so you can adhere to your organization's security policies. Using AWS KMS CMKs, you can create encryption keys and define the policies that control how these keys can be used. AWS KMS supports AWS CloudTrail, so you can audit key usage to verify that keys are being used appropriately. Using KMS CMKs also protect you from data exfiltration via snapshots as target accounts also required access to the KMS CMK via Key Policies. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using KMS CMKs with your namespace refer to the Changing the AWS KMS key for a namespace section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-workgroups-and-namespaces-rotate-kms-key.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Namespace"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessNamespace",
                        "Id": namspaceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "NamespaceName": namespaceName
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{namspaceArn}/redshift-serverless-namespace-kms-cmk-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": namspaceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.3] Redshift Serverless namespaces should use a Customer Managed Key (CMK) for encryption",
                "Description": f"Redshift Serverless namespace {namespaceName} does use a Customer Managed Key (CMK) for encryption.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using KMS CMKs with your namespace refer to the Changing the AWS KMS key for a namespace section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-workgroups-and-namespaces-rotate-kms-key.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Namespace"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessNamespace",
                        "Id": namspaceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "NamespaceName": namespaceName
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("redshift-serverless")
def redshift_serverless_workgroup_enhanced_vpc_routing_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift-Serverless.4] Redshift Serverless workgroups should enable VPC enhanced routing"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for workgroup in list_redshift_serverless_workgroups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(workgroup,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        workgroupName = workgroup["workgroupName"]
        workgroupArn = workgroup["workgroupArn"]
        if workgroup["enhancedVpcRouting"] is False:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/redshift-serverless-workgroup-vpc-enhanced-routing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.4] Redshift Serverless workgroups should enable VPC enhanced routing",
                "Description": f"Redshift Serverless workgroup {workgroupName} does not use enhanced VPC routing. When you use Amazon Redshift enhanced VPC routing, Amazon Redshift forces all COPY and UNLOAD traffic between your cluster and your data repositories through your virtual private cloud (VPC) based on the Amazon VPC service. By using enhanced VPC routing, you can use standard VPC features, such as VPC security groups, network access control lists (ACLs), VPC endpoints, VPC endpoint policies, internet gateways, and Domain Name System (DNS) servers, as described in the Amazon VPC User Guide. You use these features to tightly manage the flow of data between your Amazon Redshift cluster and other resources. When you use enhanced VPC routing to route traffic through your VPC, you can also use VPC flow logs to monitor COPY and UNLOAD traffic. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using enhanced VPC routing for Workgroups refer to the Enhanced VPC routing section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/enhanced-vpc-enabling-cluster.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Workgroup"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessWorkgroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "WorkgroupName": workgroupName
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-5",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-10",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/redshift-serverless-workgroup-vpc-enhanced-routing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.4] Redshift Serverless workgroups should enable VPC enhanced routing",
                "Description": f"Redshift Serverless workgroup {workgroupName} does use enhanced VPC routing.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using enhanced VPC routing for Workgroups refer to the Enhanced VPC routing section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/enhanced-vpc-enabling-cluster.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Workgroup"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessWorkgroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "WorkgroupName": workgroupName
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-5",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-10",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("redshift-serverless")
def redshift_serverless_workgroup_public_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift-Serverless.5] Redshift Serverless workgroups should not be configured to be publicly accessible over the internet"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for workgroup in list_redshift_serverless_workgroups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(workgroup,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        workgroupName = workgroup["workgroupName"]
        workgroupArn = workgroup["workgroupArn"]
        if workgroup["publiclyAccessible"] is True:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/redshift-serverless-workgroup-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.5] Redshift Serverless workgroups should not be configured to be publicly accessible over the internet",
                "Description": f"Redshift Serverless workgroup {workgroupName} is configured to be publicly accessible over the internet. You can configure your Amazon Redshift Serverless instance so you can query it from a SQL client in the public internet, when you turn on the publicly accessible setting, Amazon Redshift Serverless creates an Elastic IP address - a static IP address that is associated with your AWS account. Your Workgroup will still require a Security Group that allows access to port 5439 and a route to the internet, however, with permissive network configurations and a lack of mitigating controls you can have your Workgroup unnecessarily exposed to unauthorized access. Redshift Serverless Workgroups should instead use VPC Endpoints to share with other Accounts, utilize Enhanced VPC routing, enforce SSL, and use IAM Roles for UNLOAD, LOAD and COPY between AWS services. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Workgroup public access refer to the Creating a publicly accessible Amazon Redshift Serverless instance and connecting to it section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-connecting.html#serverless-publicly-accessible"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Workgroup"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessWorkgroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "WorkgroupName": workgroupName
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
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/redshift-serverless-workgroup-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.5] Redshift Serverless workgroups should not be configured to be publicly accessible over the internet",
                "Description": f"Redshift Serverless workgroup {workgroupName} is not configured to be publicly accessible over the internet.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Workgroup public access refer to the Creating a publicly accessible Amazon Redshift Serverless instance and connecting to it section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-connecting.html#serverless-publicly-accessible"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Workgroup"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessWorkgroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "WorkgroupName": workgroupName
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

@registry.register_check("redshift-serverless")
def redshift_serverless_workgroup_user_activity_configuration_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift-Serverless.6] Redshift Serverless workgroups should enable user activity logging"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for workgroup in list_redshift_serverless_workgroups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(workgroup,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        workgroupName = workgroup["workgroupName"]
        workgroupArn = workgroup["workgroupArn"]
        # Check the status / existence of the "enable_user_activity_logging" parameter
        userActivityLoggingParameter = [param for param in workgroup["configParameters"] if param["parameterKey"] == "enable_user_activity_logging"]
        if userActivityLoggingParameter:
            if userActivityLoggingParameter[0]["parameterValue"] == "true":
                enableUserActivityLogs = True
            else:
                enableUserActivityLogs = False
        else:
            enableUserActivityLogs = False

        if enableUserActivityLogs is False:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/redshift-serverless-workgroup-user-activity-configuration-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.6] Redshift Serverless workgroups should enable user activity logging",
                "Description": f"Redshift Serverless workgroup {workgroupName} does not enable user activity logging. For the user activity log, you must also enable the enable_user_activity_logging database parameter. If you enable only the audit logging feature, but not the associated parameter, the database audit logs log information for only the connection log and user log, but not for the user activity log. The enable_user_activity_logging parameter is not enabled (false) by default. You can set it to true to enable the user activity log. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on user activity logging parameter configuration refer to the Enabling logging section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html#db-auditing-enable-logging"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Workgroup"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessWorkgroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "WorkgroupName": workgroupName
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/redshift-serverless-workgroup-user-activity-configuration-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift-Serverless.6] Redshift Serverless workgroups should enable user activity logging",
                "Description": f"Redshift Serverless workgroup {workgroupName} does enable user activity logging.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on user activity logging parameter configuration refer to the Enabling logging section of the Amazon Redshift Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html#db-auditing-enable-logging"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift Serverless",
                    "AssetComponent": "Workgroup"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftServerlessWorkgroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "WorkgroupName": workgroupName
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??