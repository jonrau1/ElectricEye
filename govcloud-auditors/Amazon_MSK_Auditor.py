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
import os
import datetime
from auditors.Auditor import Auditor

# import boto3 clients
sts = boto3.client("sts")
kafka = boto3.client("kafka")
securityhub = boto3.client("securityhub")
# create env vars for account and region
awsRegion = os.environ["AWS_REGION"]
awsAccountId = sts.get_caller_identity()["Account"]
# loop through managed kafka clusters
response = kafka.list_clusters()
myMskClusters = response["ClusterInfoList"]


class InterClusterEncryptionInTransitCheck(Auditor):
    def execute(self):
        for clusters in myMskClusters:
            clusterArn = str(clusters["ClusterArn"])
            clusterName = str(clusters["ClusterName"])
            interClusterEITCheck = str(
                clusters["EncryptionInfo"]["EncryptionInTransit"]["InCluster"]
            )
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            if interClusterEITCheck != "True":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/intercluster-encryption-in-transit",
                    "ProductArn": "arn:aws-us-gov:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
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
                            "Partition": "aws-us-gov",
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
                    "ProductArn": "arn:aws-us-gov:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
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
                            "Partition": "aws-us-gov",
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


class ClientBrokerEncryptionInTransitCheck(Auditor):
    def execute(self):
        for clusters in myMskClusters:
            clusterArn = str(clusters["ClusterArn"])
            clusterName = str(clusters["ClusterName"])
            clientBrokerTlsCheck = str(
                clusters["EncryptionInfo"]["EncryptionInTransit"]["ClientBroker"]
            )
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            if clientBrokerTlsCheck != "TLS":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/client-broker-tls",
                    "ProductArn": "arn:aws-us-gov:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
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
                            "Partition": "aws-us-gov",
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
                    "ProductArn": "arn:aws-us-gov:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
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
                            "Partition": "aws-us-gov",
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


class ClientAuthenticationCheck(Auditor):
    def execute(self):
        for clusters in myMskClusters:
            clusterArn = str(clusters["ClusterArn"])
            clusterName = str(clusters["ClusterName"])
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            try:
                clientAuthCheck = str(
                    clusters["ClientAuthentication"]["Tls"][
                        "CertificateAuthorityArnList"
                    ]
                )
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/tls-client-auth",
                    "ProductArn": "arn:aws-us-gov:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[MSK.3] Managed Kafka Stream clusters should use TLS for client authentication",
                    "Description": "MSK cluster "
                    + clusterName
                    + " uses TLS for client authentication.",
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
                            "Partition": "aws-us-gov",
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
            except:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/tls-client-auth",
                    "ProductArn": "arn:aws-us-gov:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
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
                            "Partition": "aws-us-gov",
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


class ClusterEnhancedMonitoringCheck(Auditor):
    def execute(self):
        for clusters in myMskClusters:
            clusterArn = str(clusters["ClusterArn"])
            clusterName = str(clusters["ClusterName"])
            enhancedMonitoringCheck = str(clusters["EnhancedMonitoring"])
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            if enhancedMonitoringCheck == "DEFAULT":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/detailed-monitoring",
                    "ProductArn": "arn:aws-us-gov:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
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
                            "Partition": "aws-us-gov",
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
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/detailed-monitoring",
                    "ProductArn": "arn:aws-us-gov:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[MSK.4] Managed Kafka Stream clusters should use enhanced monitoring",
                    "Description": "MSK cluster "
                    + clusterName
                    + " uses enhanced monitoring.",
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
                            "Partition": "aws-us-gov",
                            "Region": awsRegion,
                            "Details": {"Other": {"ClusterName": clusterName}},
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
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
