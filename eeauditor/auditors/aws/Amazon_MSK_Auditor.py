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

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
kafka = boto3.client("kafka")

# loop through managed kafka clusters
def list_clusters(cache):
    response = cache.get("list_clusters")
    if response:
        return response
    cache["list_clusters"] = kafka.list_clusters()
    return cache["list_clusters"]

@registry.register_check("kafka")
def inter_cluster_encryption_in_transit_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MSK.1] Managed Kafka Stream clusters should have inter-cluster encryption in transit enabled"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for clusters in list_clusters(cache)["ClusterInfoList"]:
        clusterArn = str(clusters["ClusterArn"])
        clusterName = str(clusters["ClusterName"])
        interClusterEITCheck = str(clusters["EncryptionInfo"]["EncryptionInTransit"]["InCluster"])
        if interClusterEITCheck != "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/intercluster-encryption-in-transit",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[MSK.1] Managed Kafka Stream clusters should have inter-cluster encryption in transit enabled",
                "Description": "MSK cluster "
                + clusterName
                + " does not have inter-cluster encryption in transit enabled. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should have inter-cluster encryption in transit enabled refer to the How Do I Get Started with Encryption? section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-working-with-encryption.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsManagedKafkaCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterName": clusterName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/intercluster-encryption-in-transit",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[MSK.1] Managed Kafka Stream clusters should have inter-cluster encryption in transit enabled",
                "Description": "MSK cluster "
                + clusterName
                + " has inter-cluster encryption in transit enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should have inter-cluster encryption in transit enabled refer to the How Do I Get Started with Encryption? section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-working-with-encryption.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsManagedKafkaCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterName": clusterName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("kafka")
def client_broker_encryption_in_transit_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MSK.2] Managed Kafka Stream clusters should enforce TLS-only communications between clients and brokers"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for clusters in list_clusters(cache)["ClusterInfoList"]:
        clusterArn = str(clusters["ClusterArn"])
        clusterName = str(clusters["ClusterName"])
        clientBrokerTlsCheck = str(clusters["EncryptionInfo"]["EncryptionInTransit"]["ClientBroker"])
        if clientBrokerTlsCheck != "TLS":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/client-broker-tls",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[MSK.2] Managed Kafka Stream clusters should enforce TLS-only communications between clients and brokers",
                "Description": "MSK cluster "
                + clusterName
                + " does not enforce TLS-only communications between clients and brokers. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should enforce TLS-only communications between clients and brokers refer to the How Do I Get Started with Encryption? section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-working-with-encryption.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsManagedKafkaCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterName": clusterName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/client-broker-tls",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[MSK.2] Managed Kafka Stream clusters should enforce TLS-only communications between clients and brokers",
                "Description": "MSK cluster "
                + clusterName
                + " enforces TLS-only communications between clients and brokers",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should enforce TLS-only communications between clients and brokers refer to the How Do I Get Started with Encryption? section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-working-with-encryption.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsManagedKafkaCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterName": clusterName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("kafka")
def client_authentication_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MSK.3] Managed Kafka Stream clusters should use TLS for client authentication"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for clusters in list_clusters(cache)["ClusterInfoList"]:
        clusterArn = str(clusters["ClusterArn"])
        clusterName = str(clusters["ClusterName"])
        try:
            caal = clusters["ClientAuthentication"]["Tls"]["CertificateAuthorityArnList"]
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/tls-client-auth",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[MSK.3] Managed Kafka Stream clusters should use TLS for client authentication",
                "Description": f"MSK cluster {clusterName} uses TLS for client authentication.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should use TLS for client authentication refer to the Client Authentication section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsManagedKafkaCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterName": clusterName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            del caal
            yield finding
        except KeyError:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/tls-client-auth",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[MSK.3] Managed Kafka Stream clusters should use TLS for client authentication",
                "Description": "MSK cluster "
                + clusterName
                + " does not use TLS for client authentication. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should use TLS for client authentication refer to the Client Authentication section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsManagedKafkaCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterName": clusterName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("kafka")
def cluster_enhanced_monitoring_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MSK.4] Managed Kafka Stream clusters should use enhanced monitoring"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for clusters in list_clusters(cache)["ClusterInfoList"]:
        clusterArn = str(clusters["ClusterArn"])
        clusterName = str(clusters["ClusterName"])
        enhancedMonitoringCheck = str(clusters["EnhancedMonitoring"])
        if enhancedMonitoringCheck == "DEFAULT":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/detailed-monitoring",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[MSK.4] Managed Kafka Stream clusters should use enhanced monitoring",
                "Description": "MSK cluster "
                + clusterName
                + " does not use enhanced monitoring. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should use enhanced monitoring refer to the Monitoring an Amazon MSK Cluster section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/monitoring.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsManagedKafkaCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterName": clusterName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/detailed-monitoring",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[MSK.4] Managed Kafka Stream clusters should use enhanced monitoring",
                "Description": "MSK cluster " + clusterName + " uses enhanced monitoring.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should use enhanced monitoring refer to the Monitoring an Amazon MSK Cluster section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/monitoring.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsManagedKafkaCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterName": clusterName}}
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding