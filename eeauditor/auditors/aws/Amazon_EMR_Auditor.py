'''
This file is part of ElectricEye.

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
'''
import boto3
import json
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
emr = boto3.client("emr")
# loop through non-terminated EMR clusters

def list_clusters(cache):
    response = cache.get("list_clusters")
    if response:
        return response
    cache["list_clusters"] = emr.list_clusters(ClusterStates=["STARTING", "RUNNING", "WAITING"])
    return cache["list_clusters"]

@registry.register_check("emr")
def emr_cluster_security_configuration_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EMR.1] EMR Clusters should have a security configuration specified"""
    response = list_clusters(cache)
    myEmrClusters = response["Clusters"]
    for cluster in myEmrClusters:
        clusterId = str(cluster["Id"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response["Cluster"]["Id"])
            clusterName = str(response["Cluster"]["Name"])
            clusterArn = str(response["Cluster"]["ClusterArn"])
            secConfigName = str(response["Cluster"]["SecurityConfiguration"])
            # this is a Passing Check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/emr-cluster-sec-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EMR.1] EMR Clusters should have a security configuration specified",
                "Description": "EMR Cluster "
                + clusterName
                + " has a security configuration specified.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "EMR cluster security configurations cannot be specified after creation. For information on creating and attaching a security configuration refer to the Use Security Configurations to Set Up Cluster Security section of the Amazon EMR Management Guide",
                        "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security-configurations.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEmrCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "clusterId": clusterId,
                                "clusterName": clusterName,
                                "securityConfigurationName": secConfigName,
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.IP-1",
                        "NIST SP 800-53 CM-2",
                        "NIST SP 800-53 CM-3",
                        "NIST SP 800-53 CM-4",
                        "NIST SP 800-53 CM-5",
                        "NIST SP 800-53 CM-6",
                        "NIST SP 800-53 CM-7",
                        "NIST SP 800-53 CM-9",
                        "NIST SP 800-53 SA-10",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC1.4",
                        "AICPA TSC CC5.3",
                        "AICPA TSC CC6.2",
                        "AICPA TSC CC7.1",
                        "AICPA TSC CC7.3",
                        "AICPA TSC CC7.4",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.12.6.2",
                        "ISO 27001:2013 A.14.2.2",
                        "ISO 27001:2013 A.14.2.3",
                        "ISO 27001:2013 A.14.2.4",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except Exception as e:
            if str(e) == "'SecurityConfiguration'":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/emr-cluster-sec-policy-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[EMR.1] EMR Clusters should have a security configuration specified",
                    "Description": "EMR Cluster "
                    + clusterName
                    + " does not have a security configuration specified. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "EMR cluster security configurations cannot be specified after creation. For information on creating and attaching a security configuration refer to the Use Security Configurations to Set Up Cluster Security section of the Amazon EMR Management Guide",
                            "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security-configurations.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEmrCluster",
                            "Id": clusterArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"clusterId": clusterId, "clusterName": clusterName,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.IP-1",
                            "NIST SP 800-53 CM-2",
                            "NIST SP 800-53 CM-3",
                            "NIST SP 800-53 CM-4",
                            "NIST SP 800-53 CM-5",
                            "NIST SP 800-53 CM-6",
                            "NIST SP 800-53 CM-7",
                            "NIST SP 800-53 CM-9",
                            "NIST SP 800-53 SA-10",
                            "AICPA TSC A1.3",
                            "AICPA TSC CC1.4",
                            "AICPA TSC CC5.3",
                            "AICPA TSC CC6.2",
                            "AICPA TSC CC7.1",
                            "AICPA TSC CC7.3",
                            "AICPA TSC CC7.4",
                            "ISO 27001:2013 A.12.1.2",
                            "ISO 27001:2013 A.12.5.1",
                            "ISO 27001:2013 A.12.6.2",
                            "ISO 27001:2013 A.14.2.2",
                            "ISO 27001:2013 A.14.2.3",
                            "ISO 27001:2013 A.14.2.4",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                print(e)

@registry.register_check("emr")
def emr_security_config_encryption_in_transit_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EMR.2] EMR Cluster security configurations should enforce encryption in transit"""
    response = list_clusters(cache)
    myEmrClusters = response["Clusters"]
    for cluster in myEmrClusters:
        clusterId = str(cluster["Id"])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response["Cluster"]["Id"])
            clusterName = str(response["Cluster"]["Name"])
            clusterArn = str(response["Cluster"]["ClusterArn"])
            secConfigName = str(response["Cluster"]["SecurityConfiguration"])
            try:
                response = emr.describe_security_configuration(Name=secConfigName)
                configData = str(response["SecurityConfiguration"])
                jsonConfig = json.loads(configData)
                try:
                    eitCheck = str(
                        jsonConfig["EncryptionConfiguration"]["EnableInTransitEncryption"]
                    )
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    if eitCheck == "False":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": clusterArn + "/emr-encryption-in-transit-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                            "Title": "[EMR.2] EMR Cluster security configurations should enforce encryption in transit",
                            "Description": "EMR Cluster "
                            + clusterName
                            + " has a security configuration specified that does not enforce encryption in transit. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EMR cluster security configurations cannot be specified after creation. For information on encryption in transit refer to the Encryption in Transit section of the Amazon EMR Management Guide",
                                    "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-intransit",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEmrCluster",
                                    "Id": clusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "clusterId": clusterId,
                                            "clusterName": clusterName,
                                            "securityConfigurationName": secConfigName,
                                        }
                                    },
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
                            "Id": clusterArn + "/emr-encryption-in-transit-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                            "Title": "[EMR.2] EMR Cluster security configurations should enforce encryption in transit",
                            "Description": "EMR Cluster "
                            + clusterName
                            + " has a security configuration specified that enforces encryption in transit.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EMR cluster security configurations cannot be specified after creation. For information on encryption in transit refer to the Encryption in Transit section of the Amazon EMR Management Guide",
                                    "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-intransit",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEmrCluster",
                                    "Id": clusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "clusterId": clusterId,
                                            "clusterName": clusterName,
                                            "securityConfigurationName": secConfigName,
                                        }
                                    },
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
                except Exception as e:
                    print(e)
            except Exception as e:
                print(e)
        except Exception as e:
            if str(e) == "'SecurityConfiguration'":
                pass
            else:
                print(e)

@registry.register_check("emr")
def emr_security_config_encryption_at_rest_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EMR.3] EMR Cluster security configurations should enforce encryption at rest for EMRFS"""
    response = list_clusters(cache)
    myEmrClusters = response["Clusters"]
    for cluster in myEmrClusters:
        clusterId = str(cluster["Id"])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response["Cluster"]["Id"])
            clusterName = str(response["Cluster"]["Name"])
            clusterArn = str(response["Cluster"]["ClusterArn"])
            secConfigName = str(response["Cluster"]["SecurityConfiguration"])
            try:
                response = emr.describe_security_configuration(Name=secConfigName)
                configData = str(response["SecurityConfiguration"])
                jsonConfig = json.loads(configData)
                try:
                    earCheck = str(jsonConfig["EncryptionConfiguration"]["EnableAtRestEncryption"])
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    if earCheck == "False":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": clusterArn + "/emr-encryption-at-rest-emrfs-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                            "Title": "[EMR.3] EMR Cluster security configurations should enforce encryption at rest for EMRFS",
                            "Description": "EMR Cluster "
                            + clusterName
                            + " has a security configuration specified that does not enforce encryption at rest for EMRFS. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EMR cluster security configurations cannot be specified after creation. For information on encryption at rest for EMRFS refer to the Encryption at Rest for EMRFS Data in Amazon S3 section of the Amazon EMR Management Guide",
                                    "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-s3",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEmrCluster",
                                    "Id": clusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "clusterId": clusterId,
                                            "clusterName": clusterName,
                                            "securityConfigurationName": secConfigName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.DS-1",
                                    "NIST SP 800-53 MP-8",
                                    "NIST SP 800-53 SC-12",
                                    "NIST SP 800-53 SC-28",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.2.3",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": clusterArn + "/emr-encryption-at-rest-emrfs-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                            "Title": "[EMR.3] EMR Cluster security configurations should enforce encryption at rest for EMRFS",
                            "Description": "EMR Cluster "
                            + clusterName
                            + " has a security configuration specified that does not enforce encryption at rest for EMRFS. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EMR cluster security configurations cannot be specified after creation. For information on encryption at rest for EMRFS refer to the Encryption at Rest for EMRFS Data in Amazon S3 section of the Amazon EMR Management Guide",
                                    "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-s3",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEmrCluster",
                                    "Id": clusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "clusterId": clusterId,
                                            "clusterName": clusterName,
                                            "securityConfigurationName": secConfigName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.DS-1",
                                    "NIST SP 800-53 MP-8",
                                    "NIST SP 800-53 SC-12",
                                    "NIST SP 800-53 SC-28",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.2.3",
                                ],
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                except Exception as e:
                    print(e)
            except Exception as e:
                print(e)
        except Exception as e:
            if str(e) == "'SecurityConfiguration'":
                pass
            else:
                print(e)

@registry.register_check("emr")
def emr_security_config_config_ebs_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EMR.4] EMR Cluster security configurations should enforce encryption at rest for EBS"""
    response = list_clusters(cache)
    myEmrClusters = response["Clusters"]
    for cluster in myEmrClusters:
        clusterId = str(cluster["Id"])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response["Cluster"]["Id"])
            clusterName = str(response["Cluster"]["Name"])
            clusterArn = str(response["Cluster"]["ClusterArn"])
            secConfigName = str(response["Cluster"]["SecurityConfiguration"])
            try:
                response = emr.describe_security_configuration(Name=secConfigName)
                configData = str(response["SecurityConfiguration"])
                jsonConfig = json.loads(configData)
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                try:
                    ebsEncryptionCheck = str(
                        jsonConfig["EncryptionConfiguration"]["AtRestEncryptionConfiguration"][
                            "LocalDiskEncryptionConfiguration"
                        ]["EnableEbsEncryption"]
                    )
                    if ebsEncryptionCheck == "False":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": clusterArn + "/emr-encryption-at-rest-ebs-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                            "Title": "[EMR.4] EMR Cluster security configurations should enforce encryption at rest for EBS",
                            "Description": "EMR Cluster "
                            + clusterName
                            + " has a security configuration specified that does not enforce encryption at rest for EBS. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EMR cluster security configurations cannot be specified after creation. For information on encryption at rest for EBS refer to the Local Disk Encryption section of the Amazon EMR Management Guide",
                                    "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-localdisk",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEmrCluster",
                                    "Id": clusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "clusterId": clusterId,
                                            "clusterName": clusterName,
                                            "securityConfigurationName": secConfigName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.DS-1",
                                    "NIST SP 800-53 MP-8",
                                    "NIST SP 800-53 SC-12",
                                    "NIST SP 800-53 SC-28",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.2.3",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": clusterArn + "/emr-encryption-at-rest-ebs-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                            "Title": "[EMR.4] EMR Cluster security configurations should enforce encryption at rest for EBS",
                            "Description": "EMR Cluster "
                            + clusterName
                            + " has a security configuration specified that enforces encryption at rest for EBS.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EMR cluster security configurations cannot be specified after creation. For information on encryption at rest for EBS refer to the Local Disk Encryption section of the Amazon EMR Management Guide",
                                    "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-localdisk",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEmrCluster",
                                    "Id": clusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "clusterId": clusterId,
                                            "clusterName": clusterName,
                                            "securityConfigurationName": secConfigName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.DS-1",
                                    "NIST SP 800-53 MP-8",
                                    "NIST SP 800-53 SC-12",
                                    "NIST SP 800-53 SC-28",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.2.3",
                                ],
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                except Exception as e:
                    if str(e) == "'LocalDiskEncryptionConfiguration'":
                        # this is a failing check of a lesser severity
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": clusterArn + "/emr-encryption-at-rest-ebs-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                            "Title": "[EMR.4] EMR Cluster security configurations should enforce encryption at rest for EBS",
                            "Description": "EMR Cluster "
                            + clusterName
                            + " has a security configuration that does not have any local disk encryption configured. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EMR cluster security configurations cannot be specified after creation. For information on encryption at rest for EBS refer to the Local Disk Encryption section of the Amazon EMR Management Guide",
                                    "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-localdisk",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEmrCluster",
                                    "Id": clusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "clusterId": clusterId,
                                            "clusterName": clusterName,
                                            "securityConfigurationName": secConfigName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.DS-1",
                                    "NIST SP 800-53 MP-8",
                                    "NIST SP 800-53 SC-12",
                                    "NIST SP 800-53 SC-28",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.2.3",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        print(e)
            except Exception as e:
                print(e)
        except Exception as e:
            if str(e) == "'SecurityConfiguration'":
                pass
            else:
                print(e)

@registry.register_check("emr")
def emr_security_config_kerberos_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EMR.5] EMR Cluster security configurations should enable Kerberos authentication"""
    response = list_clusters(cache)
    myEmrClusters = response["Clusters"]
    for cluster in myEmrClusters:
        clusterId = str(cluster["Id"])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response["Cluster"]["Id"])
            clusterName = str(response["Cluster"]["Name"])
            clusterArn = str(response["Cluster"]["ClusterArn"])
            secConfigName = str(response["Cluster"]["SecurityConfiguration"])
            try:
                response = emr.describe_security_configuration(Name=secConfigName)
                configData = str(response["SecurityConfiguration"])
                jsonConfig = json.loads(configData)
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                try:
                    kerbCheck = str(jsonConfig["AuthenticationConfiguration"])
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": clusterArn + "/emr-kerberos-authn-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[EMR.5] EMR Cluster security configurations should enable Kerberos authentication",
                        "Description": "EMR Cluster "
                        + clusterName
                        + " has a security configuration specified that does not enable Kerberos authentication. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "EMR cluster security configurations cannot be specified after creation. For information on Kerberized EMR clusters refer to the Use Kerberos Authentication section of the Amazon EMR Management Guide",
                                "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsEmrCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "clusterId": clusterId,
                                        "clusterName": clusterName,
                                        "securityConfigurationName": secConfigName,
                                        "authenticationConfiguration": kerbCheck,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-6",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-2",
                                "NIST SP 800-53 AC-3",
                                "NIST SP 800-53 AC-16",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-24",
                                "NIST SP 800-53 IA-1",
                                "NIST SP 800-53 IA-2",
                                "NIST SP 800-53 IA-4",
                                "NIST SP 800-53 IA-5",
                                "NIST SP 800-53 IA-8",
                                "NIST SP 800-53 PE-2",
                                "NIST SP 800-53 PS-3",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.7.1.1",
                                "ISO 27001:2013 A.9.2.1",
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                except Exception as e:
                    if str(e) == "'AuthenticationConfiguration'":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": clusterArn + "/emr-kerberos-authn-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                            "Title": "[EMR.5] EMR Cluster security configurations should enable Kerberos authentication",
                            "Description": "EMR Cluster "
                            + clusterName
                            + " has a security configuration specified that does not enable Kerberos authentication. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EMR cluster security configurations cannot be specified after creation. For information on Kerberized EMR clusters refer to the Use Kerberos Authentication section of the Amazon EMR Management Guide",
                                    "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEmrCluster",
                                    "Id": clusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "clusterId": clusterId,
                                            "clusterName": clusterName,
                                            "securityConfigurationName": secConfigName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.AC-6",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-2",
                                    "NIST SP 800-53 AC-3",
                                    "NIST SP 800-53 AC-16",
                                    "NIST SP 800-53 AC-19",
                                    "NIST SP 800-53 AC-24",
                                    "NIST SP 800-53 IA-1",
                                    "NIST SP 800-53 IA-2",
                                    "NIST SP 800-53 IA-4",
                                    "NIST SP 800-53 IA-5",
                                    "NIST SP 800-53 IA-8",
                                    "NIST SP 800-53 PE-2",
                                    "NIST SP 800-53 PS-3",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.7.1.1",
                                    "ISO 27001:2013 A.9.2.1",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        print(e)
            except Exception as e:
                print(e)
        except Exception as e:
            if str(e) == "'SecurityConfiguration'":
                pass
            else:
                print(e)

@registry.register_check("emr")
def emr_cluster_termination_protection_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EMR.6] EMR Clusters should have termination protection enabled"""
    response = list_clusters(cache)
    myEmrClusters = response["Clusters"]
    for cluster in myEmrClusters:
        clusterId = str(cluster["Id"])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response["Cluster"]["Id"])
            clusterName = str(response["Cluster"]["Name"])
            clusterArn = str(response["Cluster"]["ClusterArn"])
            delProtectCheck = str(response["Cluster"]["TerminationProtected"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if delProtectCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/emr-termination-protection-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[EMR.6] EMR Clusters should have termination protection enabled",
                    "Description": "EMR Cluster "
                    + clusterName
                    + " does not have termination protection enabled. When termination protection is enabled on a long-running cluster, you can still terminate the cluster, but you must explicitly remove termination protection from the cluster first. This helps ensure that EC2 instances are not shut down by an accident or error. If this configuration is not intentional refer to the remediation section.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on EMR termination protection refer to the Using Termination Protection section of the Amazon EMR Management Guide",
                            "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/UsingEMR_TerminationProtection.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEmrCluster",
                            "Id": clusterArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"clusterId": clusterId, "clusterName": clusterName,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF ID.BE-5",
                            "NIST CSF PR.PT-5",
                            "NIST SP 800-53 CP-2",
                            "NIST SP 800-53 CP-11",
                            "NIST SP 800-53 SA-13",
                            "NIST SP 800-53 SA14",
                            "AICPA TSC CC3.1",
                            "AICPA TSC A1.2",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.17.1.1",
                            "ISO 27001:2013 A.17.1.2",
                            "ISO 27001:2013 A.17.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/emr-termination-protection-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[EMR.6] EMR Clusters should have termination protection enabled",
                    "Description": "EMR Cluster "
                    + clusterName
                    + " has termination protection enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on EMR termination protection refer to the Using Termination Protection section of the Amazon EMR Management Guide",
                            "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/UsingEMR_TerminationProtection.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEmrCluster",
                            "Id": clusterArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"clusterId": clusterId, "clusterName": clusterName,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF ID.BE-5",
                            "NIST CSF PR.PT-5",
                            "NIST SP 800-53 CP-2",
                            "NIST SP 800-53 CP-11",
                            "NIST SP 800-53 SA-13",
                            "NIST SP 800-53 SA14",
                            "AICPA TSC CC3.1",
                            "AICPA TSC A1.2",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.17.1.1",
                            "ISO 27001:2013 A.17.1.2",
                            "ISO 27001:2013 A.17.2.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("emr")
def emr_cluster_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EMR.7] EMR Clusters should have logging enabled"""
    response = list_clusters(cache)
    myEmrClusters = response["Clusters"]
    for cluster in myEmrClusters:
        clusterId = str(cluster["Id"])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response["Cluster"]["Id"])
            clusterName = str(response["Cluster"]["Name"])
            clusterArn = str(response["Cluster"]["ClusterArn"])
            logUriCheck = str(response["Cluster"]["LogUri"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/emr-cluster-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EMR.7] EMR Clusters should have logging enabled",
                "Description": "EMR Cluster " + clusterName + " does has logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on EMR cluster logging and debugging refer to the Configure Cluster Logging and Debugging section of the Amazon EMR Management Guide",
                        "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-debugging.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEmrCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "clusterId": clusterId,
                                "clusterName": clusterName,
                                "logPathUri": logUriCheck,
                            }
                        },
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
        except Exception as e:
            if str(e) == "'LogUri'":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterArn + "/emr-cluster-logging-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[EMR.7] EMR Clusters should have logging enabled",
                    "Description": "EMR Cluster "
                    + clusterName
                    + " does not have logging enabled. You do not need to enable anything to have log files written on the master node. This is the default behavior of Amazon EMR and Hadoop, but can be turned off on creation. If this configuration is not intentional refer to the remediation section.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on EMR cluster logging and debugging refer to the Configure Cluster Logging and Debugging section of the Amazon EMR Management Guide",
                            "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-debugging.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEmrCluster",
                            "Id": clusterArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"clusterId": clusterId, "clusterName": clusterName,}
                            },
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
                print(e)

@registry.register_check("emr")
def emr_cluster_block_secgroup_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EMR.8] EMR account-level public security group access block should be enabled"""
    response = list_clusters(cache)
    myEmrClusters = response["Clusters"]
    try:
        response = emr.get_block_public_access_configuration()
        blockPubSgCheck = str(
            response["BlockPublicAccessConfiguration"]["BlockPublicSecurityGroupRules"]
        )
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if blockPubSgCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/account-level-emr-block-public-sg-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": awsAccountId + "/" + awsRegion + "/" + "emr-acct-sg-block",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[EMR.8] EMR account-level public security group access block should be enabled",
                "Description": "EMR account-level public security group access block is not enabled for "
                + awsAccountId
                + " in AWS region "
                + awsRegion
                + ". Amazon EMR block public access prevents a cluster from launching when any security group associated with the cluster has a rule that allows inbound traffic from IPv4 0.0.0.0/0 or IPv6 ::/0 (public access) on a port, unless the port has been specified as an exception. Port 22 is an exception by default. This is the default behavior of Amazon EMR and Hadoop, but can be turned off on creation. If this configuration is not intentional refer to the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on EMR Block Public Access refer to the Using Amazon EMR Block Public Access section of the Amazon EMR Management Guide",
                        "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-block-public-access.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-3",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-17",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-20",
                        "NIST SP 800-53 SC-15",
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
                "Id": awsAccountId + "/account-level-emr-block-public-sg-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": awsAccountId + "/" + awsRegion + "/" + "emr-acct-sg-block",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EMR.8] EMR account-level public security group access block should be enabled",
                "Description": "EMR account-level public security group access block is not enabled for "
                + awsAccountId
                + " in AWS region "
                + awsRegion
                + ". Amazon EMR block public access prevents a cluster from launching when any security group associated with the cluster has a rule that allows inbound traffic from IPv4 0.0.0.0/0 or IPv6 ::/0 (public access) on a port, unless the port has been specified as an exception. Port 22 is an exception by default. This is the default behavior of Amazon EMR and Hadoop, but can be turned off on creation. If this configuration is not intentional refer to the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on EMR Block Public Access refer to the Using Amazon EMR Block Public Access section of the Amazon EMR Management Guide",
                        "Url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-block-public-access.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-3",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-17",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-20",
                        "NIST SP 800-53 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
    except Exception as e:
        print(e)