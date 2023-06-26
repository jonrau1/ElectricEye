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

def list_clusters(cache, session):
    response = cache.get("list_clusters")
    if response:
        return response
    
    kafka = session.client("kafka")

    cache["list_clusters"] = kafka.list_clusters()["ClusterInfoList"]
    return cache["list_clusters"]

@registry.register_check("kafka")
def aws_msk_inter_cluster_encryption_in_transit_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MSK.1] Amazon Managed Streaming for Apache Kafka (MSK) clusters should have inter-cluster encryption in transit enabled"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for clusters in list_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clusters,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterArn = clusters["ClusterArn"]
        clusterName = clusters["ClusterName"]
        if clusters["EncryptionInfo"]["EncryptionInTransit"]["InCluster"] is not True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/intercluster-encryption-in-transit",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{clusterArn}/intercluster-encryption-in-transit",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[MSK.1] Amazon Managed Streaming for Apache Kafka (MSK) clusters should have inter-cluster encryption in transit enabled",
                "Description": f"Amazon Managed Streaming for Apache Kafka (MSK) cluster {clusterName} does not have inter-cluster encryption in transit enabled. Amazon MSK uses TLS 1.2. By default, it encrypts data in transit between the brokers of your MSK cluster. You can override this default at the time you create the cluster. Amazon MSK brokers use public AWS Certificate Manager certificates. Therefore, any truststore that trusts Amazon Trust Services also trusts the certificates of Amazon MSK brokers. While Amazon highly recommends enabling in-transit encryption, it can add additional CPU overhead and a few milliseconds of latency. Most use cases aren't sensitive to these differences, however, and the magnitude of impact depends on the configuration of your cluster, clients, and usage profile. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should have inter-cluster encryption in transit enabled refer to the How Do I Get Started with Encryption? section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-working-with-encryption.html"
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
                    "AssetService": "Amazon Managed Streaming for Apache Kafka",
                    "AssetType": "Cluster"
                },
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
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/intercluster-encryption-in-transit",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{clusterArn}/intercluster-encryption-in-transit",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[MSK.1] Amazon Managed Streaming for Apache Kafka (MSK) clusters should have inter-cluster encryption in transit enabled",
                "Description": f"Amazon Managed Streaming for Apache Kafka (MSK) cluster {clusterName} does have inter-cluster encryption in transit enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should have inter-cluster encryption in transit enabled refer to the How Do I Get Started with Encryption? section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-working-with-encryption.html"
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
                    "AssetService": "Amazon Managed Streaming for Apache Kafka",
                    "AssetType": "Cluster"
                },
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
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
            yield finding

@registry.register_check("kafka")
def aws_msk_client_broker_encryption_in_transit_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MSK.2] Amazon Managed Streaming for Apache Kafka (MSK) clusters should enforce TLS-only communications between clients and brokers"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for clusters in list_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clusters,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterArn = clusters["ClusterArn"]
        clusterName = clusters["ClusterName"]
        if clusters["EncryptionInfo"]["EncryptionInTransit"]["ClientBroker"] != "TLS":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/client-broker-tls-communication-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{clusterArn}/client-broker-tls-communication-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[MSK.2] Amazon Managed Streaming for Apache Kafka (MSK) clusters should enforce TLS-only communications between clients and brokers",
                "Description": f"Amazon Managed Streaming for Apache Kafka (MSK) cluster {clusterName} does not enforce TLS-only communications between clients and brokers. Amazon MSK uses TLS 1.2. By default, it encrypts data in transit between the brokers of your MSK cluster. You can override this default at the time you create the cluster. For communication between clients and brokers, you must specify one of the following three settings: Only allow TLS encrypted data. This is the default setting, Allow both plaintext, as well as TLS encrypted data, or Only allow plaintext data. Amazon MSK brokers use public AWS Certificate Manager certificates. Therefore, any truststore that trusts Amazon Trust Services also trusts the certificates of Amazon MSK brokers. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should enforce TLS-only communications between clients and brokers refer to the How Do I Get Started with Encryption? section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-working-with-encryption.html"
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
                    "AssetService": "Amazon Managed Streaming for Apache Kafka",
                    "AssetType": "Cluster"
                },
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
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/client-broker-tls-communication-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{clusterArn}/client-broker-tls-communication-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[MSK.2] Amazon Managed Streaming for Apache Kafka (MSK) clusters should enforce TLS-only communications between clients and brokers",
                "Description": f"Amazon Managed Streaming for Apache Kafka (MSK) cluster {clusterName} does enforce TLS-only communications between clients and brokers.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should enforce TLS-only communications between clients and brokers refer to the How Do I Get Started with Encryption? section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-working-with-encryption.html",
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
                    "AssetService": "Amazon Managed Streaming for Apache Kafka",
                    "AssetType": "Cluster"
                },
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
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
            yield finding

@registry.register_check("kafka")
def aws_msk_client_authentication_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MSK.3] Amazon Managed Streaming for Apache Kafka (MSK) clusters should use TLS for client authentication"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for clusters in list_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clusters,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterArn = clusters["ClusterArn"]
        clusterName = clusters["ClusterName"]
        # Determine if Client comms TLS check
        try:
            clusters["ClientAuthentication"]["Tls"]["CertificateAuthorityArnList"]
            clientTlsComms = True
        except KeyError:
            clientTlsComms = False
        # this is a failing finding
        if clientTlsComms is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/tls-client-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{clusterArn}/tls-client-auth-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[MSK.3] Amazon Managed Streaming for Apache Kafka (MSK) clusters should use TLS for client authentication",
                "Description": f"Amazon Managed Streaming for Apache Kafka (MSK) cluster {clusterName} does not use TLS for client authentication. You can enable client authentication with TLS for connections from your applications to your Amazon MSK brokers and ZooKeeper nodes. To use client authentication, you need an AWS Private CA. The AWS Private CA can be either in the same AWS account as your cluster, or in a different account. For information about AWS Private CAs, see Creating and Managing a AWS Private CA. Amazon MSK doesn't support certificate revocation lists (CRLs). To control access to your cluster topics or block compromised certificates, use Apache Kafka ACLs and AWS security groups. For information about using Apache Kafka ACLs, see Apache Kafka ACLs. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should use TLS for client authentication refer to the Client Authentication section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html",
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
                    "AssetService": "Amazon Managed Streaming for Apache Kafka",
                    "AssetType": "Cluster"
                },
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
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/tls-client-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{clusterArn}/tls-client-auth-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[MSK.3] Amazon Managed Streaming for Apache Kafka (MSK) clusters should use TLS for client authentication",
                "Description": f"Amazon Managed Streaming for Apache Kafka (MSK) cluster {clusterName} does use TLS for client authentication.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should use TLS for client authentication refer to the Client Authentication section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html",
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
                    "AssetService": "Amazon Managed Streaming for Apache Kafka",
                    "AssetType": "Cluster"
                },
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
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
            yield finding

@registry.register_check("kafka")
def aws_msk_cluster_enhanced_monitoring_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MSK.4] Amazon Managed Streaming for Apache Kafka (MSK) clusters should use enhanced monitoring"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for clusters in list_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clusters,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterArn = clusters["ClusterArn"]
        clusterName = clusters["ClusterName"]
        if clusters["EnhancedMonitoring"] == "DEFAULT":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/msk-detailed-monitoring-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{clusterArn}/msk-detailed-monitoring-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[MSK.4] Amazon Managed Streaming for Apache Kafka (MSK) clusters should use enhanced monitoring",
                "Description": f"Amazon Managed Streaming for Apache Kafka (MSK) cluster {clusterName} does not use enhanced monitoring. Amazon MSK integrates with Amazon CloudWatch so that you can collect, view, and analyze CloudWatch metrics for your Amazon MSK cluster. The metrics that you configure for your MSK cluster are automatically collected and pushed to CloudWatch. You can set the monitoring level for an MSK cluster to one of the following: DEFAULT, PER_BROKER, PER_TOPIC_PER_BROKER, or PER_TOPIC_PER_PARTITION. The tables in the following sections show all the metrics that are available starting at each monitoring level. DEFAULT-level metrics are free. Pricing for other metrics is described in the Amazon CloudWatch pricing page. When you set the monitoring level to anything other than DEFAULT, you get the metrics described in the remediation guide, and is considered 'enhanced' monitoring. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should use enhanced monitoring refer to the Monitoring an Amazon MSK Cluster section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/monitoring.html"
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
                    "AssetService": "Amazon Managed Streaming for Apache Kafka",
                    "AssetType": "Cluster"
                },
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
                "Id": f"{clusterArn}/msk-detailed-monitoring-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{clusterArn}/msk-detailed-monitoring-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[MSK.4] Amazon Managed Streaming for Apache Kafka (MSK) clusters should use enhanced monitoring",
                "Description": f"Amazon Managed Streaming for Apache Kafka (MSK) cluster {clusterName} does use enhanced monitoring.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should use enhanced monitoring refer to the Monitoring an Amazon MSK Cluster section of the Amazon Managed Streaming for Apache Kakfa Developer Guide",
                        "Url": "https://docs.aws.amazon.com/msk/latest/developerguide/monitoring.html",
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
                    "AssetService": "Amazon Managed Streaming for Apache Kafka",
                    "AssetType": "Cluster"
                },
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
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??