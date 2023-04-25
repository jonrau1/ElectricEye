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

registry = CheckRegister()

supportedK8sVersions = ["1.25", "1.24", "1.23", "1.22"]

@registry.register_check("eks")
def eks_public_endpoint_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EKS.1] Elastic Kubernetes Service (EKS) cluster API servers should not be accessible from the internet"""
    eks = session.client("eks")
    # loop through EKS clusters
    for clusters in eks.list_clusters(maxResults=100)["clusters"]:
        cluster = str(clusters)
        try:
            response = eks.describe_cluster(name=cluster)
            clusterName = str(response["cluster"]["name"])
            clusterArn = str(response["cluster"]["arn"])
            k8sVersion = str(response["cluster"]["version"])
            eksPublicAccessCheck = str(
                response["cluster"]["resourcesVpcConfig"]["endpointPublicAccess"]
            )
            # ISO Time
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if eksPublicAccessCheck == "True":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/public-endpoint-access-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterName,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "CRITICAL"},
                    "Confidence": 99,
                    "Title": "[EKS.1] Elastic Kubernetes Service (EKS) cluster API servers should not be accessible from the internet",
                    "Description": "Elastic Kubernetes Service (EKS) cluster "
                    + clusterName
                    + " API server is accessible from the internet. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your EKS cluster is not intended to be public refer to the Amazon EKS Cluster Endpoint Access Control section of the EKS user guide",
                            "Url": "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEksCluster",
                            "Id": clusterArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEksCluster": {
                                    "Name": clusterName,
                                    "Arn": clusterArn,
                                    "Version": k8sVersion
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
                            "ISO 27001:2013 A.13.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/public-endpoint-access-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterName,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[EKS.1] Elastic Kubernetes Service (EKS) cluster API servers should not be accessible from the internet",
                    "Description": "Elastic Kubernetes Service (EKS) cluster "
                    + clusterName
                    + " API server is not accessible from the internet.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your EKS cluster is not intended to be public refer to the Amazon EKS Cluster Endpoint Access Control section of the EKS user guide",
                            "Url": "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEksCluster",
                            "Id": clusterArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEksCluster": {
                                    "Name": clusterName,
                                    "Arn": clusterArn,
                                    "Version": k8sVersion
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
                            "ISO 27001:2013 A.13.2.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("eks")
def eks_latest_k8s_version_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EKS.2] Elastic Kubernetes Service (EKS) clusters should use the latest Kubernetes version"""
    eks = session.client("eks")
    # loop through EKS clusters
    for clusters in eks.list_clusters(maxResults=100)["clusters"]:
        cluster = str(clusters)
        try:
            response = eks.describe_cluster(name=cluster)
            clusterName = str(response["cluster"]["name"])
            clusterArn = str(response["cluster"]["arn"])
            k8sVersion = str(response["cluster"]["version"])
            # ISO Time
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if k8sVersion not in supportedK8sVersions:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/eks-latest-k8s-version-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterName,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices",],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[EKS.2] Elastic Kubernetes Service (EKS) clusters should use the latest Kubernetes version",
                    "Description": "Elastic Kubernetes Service (EKS) cluster "
                    + clusterName
                    + " is using Kubernetes version "
                    + k8sVersion
                    + ". Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "Unless your application requires a specific version of Kubernetes, AWS recommends you choose the latest available Kubernetes version supported by Amazon EKS for your clusters. For upgrade information refer to the Updating an Amazon EKS Cluster Kubernetes Version section of the EKS user guide",
                            "Url": "https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEksCluster",
                            "Id": clusterArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEksCluster": {
                                    "Name": clusterName,
                                    "Arn": clusterArn,
                                    "Version": k8sVersion
                                }
                            }
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
                            "ISO 27001:2013 A.12.5.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/eks-latest-k8s-version-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterName,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices",],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[EKS.2] Elastic Kubernetes Service (EKS) clusters should use the latest Kubernetes version",
                    "Description": "Elastic Kubernetes Service (EKS) cluster "
                    + clusterName
                    + " is using Kubernetes version "
                    + k8sVersion,
                    "Remediation": {
                        "Recommendation": {
                            "Text": "Unless your application requires a specific version of Kubernetes, AWS recommends you choose the latest available Kubernetes version supported by Amazon EKS for your clusters. For upgrade information refer to the Updating an Amazon EKS Cluster Kubernetes Version section of the EKS user guide",
                            "Url": "https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEksCluster",
                            "Id": clusterArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEksCluster": {
                                    "Name": clusterName,
                                    "Arn": clusterArn,
                                    "Version": k8sVersion
                                }
                            }
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
                            "ISO 27001:2013 A.12.5.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("eks")
def eks_logging_audit_auth_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EKS.3] Elastic Kubernetes Service (EKS) clusters should have authenticator and/or audit logging enabled"""
    eks = session.client("eks")
    
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

    # loop through EKS clusters
    for clusters in eks.list_clusters(maxResults=100)["clusters"]:
        cluster = str(clusters)
        try:
            response = eks.describe_cluster(name=cluster)
            clusterName = str(response["cluster"]["name"])
            clusterArn = str(response["cluster"]["arn"])
            k8sVersion = str(response["cluster"]["version"])
            logInfo = response["cluster"]["logging"]["clusterLogging"]
            for logs in logInfo:
                if str(logs["enabled"]) == "True":
                    logTypes = logs["types"]
                    # list comprehension
                    if ("authenticator" or "audit") in logTypes:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": clusterArn + "/eks-logging-audit-auth-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": clusterName,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[EKS.3] Elastic Kubernetes Service (EKS) clusters should have authenticator and/or audit logging enabled",
                            "Description": "Elastic Kubernetes Service (EKS) cluster "
                            + clusterName
                            + " has authenticator and/or audit logging enabled.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To enable logging for your cluster refer to the Amazon EKS Control Plane Logging section of the EKS user guide",
                                    "Url": "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEksCluster",
                                    "Id": clusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsEksCluster": {
                                            "Name": clusterName,
                                            "Arn": clusterArn,
                                            "Version": k8sVersion
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-3",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 IR-5",
                                    "NIST SP 800-53 Rev. 4 IR-8",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.12.4.1",
                                    "ISO 27001:2013 A.16.1.7",
                                ],
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": clusterArn + "/eks-logging-audit-auth-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": clusterName,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[EKS.3] Elastic Kubernetes Service (EKS) clusters should have authenticator and/or audit logging enabled",
                            "Description": "Elastic Kubernetes Service (EKS) cluster "
                            + clusterName
                            + " does not have authenticator or audit logging enabled. Refer to the remediation instructions if this configuration is not intended",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To enable logging for your cluster refer to the Amazon EKS Control Plane Logging section of the EKS user guide",
                                    "Url": "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEksCluster",
                                    "Id": clusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsEksCluster": {
                                            "Name": clusterName,
                                            "Arn": clusterArn,
                                            "Version": k8sVersion
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-3",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 IR-5",
                                    "NIST SP 800-53 Rev. 4 IR-8",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.12.4.1",
                                    "ISO 27001:2013 A.16.1.7",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
        except Exception as e:
            print(f"Issue found with EKS Logging Check {e}")
            continue

@registry.register_check("eks")
def eks_secrets_envelope_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EKS.4] Elastic Kubernetes Service (EKS) clusters API servers should have envelope encryption for secrets configured"""
    eks = session.client("eks")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # loop through EKS clusters
    for clusters in eks.list_clusters(maxResults=100)["clusters"]:
        cluster = str(clusters)
        try:
            response = eks.describe_cluster(name=cluster)["cluster"]
            clusterName = str(response["name"])
            clusterArn = str(response["arn"])
            k8sVersion = str(response["version"])    
            try:
                # There could technically be more than one thing here, one day, but...whatever?
                # This is a Passing Finding!
                k8sSecretKey = str(response["encryptionConfig"][0]["provider"]["keyArn"])
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/secrets-envelope-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterName,
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
                    "Title": "[EKS.4] Elastic Kubernetes Service (EKS) clusters API servers should have envelope encryption for secrets configured",
                    "Description": "Elastic Kubernetes Service (EKS) cluster "
                    + clusterName
                    + " has envelope encryption for secrets configured.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "EKS allows you to implement envelope encryption of Kubernetes secrets using AWS Key Management Service (KMS) keys. To enable it refer to the Enabling envelope encryption on an existing cluster section of the EKS user guide",
                            "Url": "https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html#enable-kms"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEksCluster",
                            "Id": clusterArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEksCluster": {
                                    "Name": clusterName,
                                    "Arn": clusterArn,
                                    "Version": k8sVersion
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
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            except KeyError:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/secrets-envelope-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterName,
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
                    "Title": "[EKS.4] Elastic Kubernetes Service (EKS) clusters API servers should have envelope encryption for secrets configured",
                    "Description": "Elastic Kubernetes Service (EKS) cluster "
                    + clusterName
                    + " does not have envelope encryption for secrets configured. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "EKS allows you to implement envelope encryption of Kubernetes secrets using AWS Key Management Service (KMS) keys. To enable it refer to the Enabling envelope encryption on an existing cluster section of the EKS user guide",
                            "Url": "https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html#enable-kms"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEksCluster",
                            "Id": clusterArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEksCluster": {
                                    "Name": clusterName,
                                    "Arn": clusterArn,
                                    "Version": k8sVersion
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
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
        except Exception as e:
            print(f"Issue with EKS Envelope Encryption check {e}")
            continue