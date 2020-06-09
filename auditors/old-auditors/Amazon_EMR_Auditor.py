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
import json
import datetime
import os
# import boto3 clients
securityhub = boto3.client('securityhub')
emr = boto3.client('emr')
sts = boto3.client('sts')
# create account id & region variables
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through non-terminated EMR clusters
try:
    response = emr.list_clusters(ClusterStates=['STARTING','RUNNING','WAITING'])
    myEmrClusters = response['Clusters']
except Exception as e:
    print(e)

def emr_cluster_security_configuration_check():
    for cluster in myEmrClusters:
        clusterId = str(cluster['Id'])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response['Cluster']['Id'])
            clusterName = str(response['Cluster']['Name'])
            clusterArn = str(response['Cluster']['ClusterArn'])
            secConfigName = str(response['Cluster']['SecurityConfiguration'])
            # this is a Passing Check
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/emr-cluster-sec-policy-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[EMR.1] EMR Clusters should have a security configuration specified',
                            'Description': 'EMR Cluster ' + clusterName + ' has a security configuration specified.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'EMR cluster security configurations cannot be specified after creation. For information on creating and attaching a security configuration refer to the Use Security Configurations to Set Up Cluster Security section of the Amazon EMR Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security-configurations.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEmrCluster',
                                    'Id': clusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 
                                            'clusterId': clusterId,
                                            'clusterName': clusterName,
                                            'securityConfigurationName': secConfigName
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.IP-1',
                                    'NIST SP 800-53 CM-2',
                                    'NIST SP 800-53 CM-3',
                                    'NIST SP 800-53 CM-4',
                                    'NIST SP 800-53 CM-5',
                                    'NIST SP 800-53 CM-6',
                                    'NIST SP 800-53 CM-7',
                                    'NIST SP 800-53 CM-9',
                                    'NIST SP 800-53 SA-10',
                                    'AICPA TSC A1.3',
                                    'AICPA TSC CC1.4',
                                    'AICPA TSC CC5.3',
                                    'AICPA TSC CC6.2',
                                    'AICPA TSC CC7.1',
                                    'AICPA TSC CC7.3',
                                    'AICPA TSC CC7.4',
                                    'ISO 27001:2013 A.12.1.2',
                                    'ISO 27001:2013 A.12.5.1',
                                    'ISO 27001:2013 A.12.6.2',
                                    'ISO 27001:2013 A.14.2.2',
                                    'ISO 27001:2013 A.14.2.3',
                                    'ISO 27001:2013 A.14.2.4'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        except Exception as e:
            if str(e) == "'SecurityConfiguration'":
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterArn + '/emr-cluster-sec-policy-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'MEDIUM' },
                                'Confidence': 99,
                                'Title': '[EMR.1] EMR Clusters should have a security configuration specified',
                                'Description': 'EMR Cluster ' + clusterName + ' does not have a security configuration specified. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'EMR cluster security configurations cannot be specified after creation. For information on creating and attaching a security configuration refer to the Use Security Configurations to Set Up Cluster Security section of the Amazon EMR Management Guide',
                                        'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security-configurations.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEmrCluster',
                                        'Id': clusterArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'clusterId': clusterId,
                                                'clusterName': clusterName
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'FAILED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.IP-1',
                                        'NIST SP 800-53 CM-2',
                                        'NIST SP 800-53 CM-3',
                                        'NIST SP 800-53 CM-4',
                                        'NIST SP 800-53 CM-5',
                                        'NIST SP 800-53 CM-6',
                                        'NIST SP 800-53 CM-7',
                                        'NIST SP 800-53 CM-9',
                                        'NIST SP 800-53 SA-10',
                                        'AICPA TSC A1.3',
                                        'AICPA TSC CC1.4',
                                        'AICPA TSC CC5.3',
                                        'AICPA TSC CC6.2',
                                        'AICPA TSC CC7.1',
                                        'AICPA TSC CC7.3',
                                        'AICPA TSC CC7.4',
                                        'ISO 27001:2013 A.12.1.2',
                                        'ISO 27001:2013 A.12.5.1',
                                        'ISO 27001:2013 A.12.6.2',
                                        'ISO 27001:2013 A.14.2.2',
                                        'ISO 27001:2013 A.14.2.3',
                                        'ISO 27001:2013 A.14.2.4'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'NEW'
                                },
                                'RecordState': 'ACTIVE'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
            else:
                print(e)

def emr_security_config_encryption_in_transit_check():
    for cluster in myEmrClusters:
        clusterId = str(cluster['Id'])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response['Cluster']['Id'])
            clusterName = str(response['Cluster']['Name'])
            clusterArn = str(response['Cluster']['ClusterArn'])
            secConfigName = str(response['Cluster']['SecurityConfiguration'])
            try:
                response = emr.describe_security_configuration(Name=secConfigName)
                configData = str(response['SecurityConfiguration'])
                jsonConfig = json.loads(configData)
                try:
                    eitCheck = str(jsonConfig['EncryptionConfiguration']['EnableInTransitEncryption'])
                    if eitCheck == 'False':
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': clusterArn + '/emr-encryption-in-transit-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': clusterArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'HIGH' },
                                        'Confidence': 99,
                                        'Title': '[EMR.2] EMR Cluster security configurations should enforce encryption in transit',
                                        'Description': 'EMR Cluster ' + clusterName + ' has a security configuration specified that does not enforce encryption in transit. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'EMR cluster security configurations cannot be specified after creation. For information on encryption in transit refer to the Encryption in Transit section of the Amazon EMR Management Guide',
                                                'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-intransit'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'AwsEmrCluster',
                                                'Id': clusterArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'clusterId': clusterId,
                                                        'clusterName': clusterName,
                                                        'securityConfigurationName': secConfigName
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 
                                            'Status': 'FAILED',
                                            'RelatedRequirements': [
                                                'NIST CSF PR.DS-2',
                                                'NIST SP 800-53 SC-8',
                                                'NIST SP 800-53 SC-11',
                                                'NIST SP 800-53 SC-12',
                                                'AICPA TSC CC6.1',
                                                'ISO 27001:2013 A.8.2.3',
                                                'ISO 27001:2013 A.13.1.1',
                                                'ISO 27001:2013 A.13.2.1',
                                                'ISO 27001:2013 A.13.2.3',
                                                'ISO 27001:2013 A.14.1.2',
                                                'ISO 27001:2013 A.14.1.3'
                                            ]
                                        },
                                        'Workflow': {
                                            'Status': 'NEW'
                                        },
                                        'RecordState': 'ACTIVE'
                                    }
                                ]
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                    else:
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': clusterArn + '/emr-encryption-in-transit-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': clusterArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'INFORMATIONAL' },
                                        'Confidence': 99,
                                        'Title': '[EMR.2] EMR Cluster security configurations should enforce encryption in transit',
                                        'Description': 'EMR Cluster ' + clusterName + ' has a security configuration specified that enforces encryption in transit.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'EMR cluster security configurations cannot be specified after creation. For information on encryption in transit refer to the Encryption in Transit section of the Amazon EMR Management Guide',
                                                'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-intransit'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'AwsEmrCluster',
                                                'Id': clusterArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'clusterId': clusterId,
                                                        'clusterName': clusterName,
                                                        'securityConfigurationName': secConfigName
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 
                                            'Status': 'PASSED',
                                            'RelatedRequirements': [
                                                'NIST CSF PR.DS-2',
                                                'NIST SP 800-53 SC-8',
                                                'NIST SP 800-53 SC-11',
                                                'NIST SP 800-53 SC-12',
                                                'AICPA TSC CC6.1',
                                                'ISO 27001:2013 A.8.2.3',
                                                'ISO 27001:2013 A.13.1.1',
                                                'ISO 27001:2013 A.13.2.1',
                                                'ISO 27001:2013 A.13.2.3',
                                                'ISO 27001:2013 A.14.1.2',
                                                'ISO 27001:2013 A.14.1.3'
                                            ]
                                        },
                                        'Workflow': {
                                            'Status': 'RESOLVED'
                                        },
                                        'RecordState': 'ARCHIVED'
                                    }
                                ]
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                except Exception as e:
                    print(e)
            except Exception as e:
                print(e)
        except Exception as e:
            if str(e) == "'SecurityConfiguration'":
                pass
            else:
                print(e)
    
def emr_security_config_encryption_at_rest_check():
    for cluster in myEmrClusters:
        clusterId = str(cluster['Id'])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response['Cluster']['Id'])
            clusterName = str(response['Cluster']['Name'])
            clusterArn = str(response['Cluster']['ClusterArn'])
            secConfigName = str(response['Cluster']['SecurityConfiguration'])
            try:
                response = emr.describe_security_configuration(Name=secConfigName)
                configData = str(response['SecurityConfiguration'])
                jsonConfig = json.loads(configData)
                try:
                    earCheck = str(jsonConfig['EncryptionConfiguration']['EnableAtRestEncryption'])
                    if earCheck == 'False':
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': clusterArn + '/emr-encryption-at-rest-emrfs-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': clusterArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'HIGH' },
                                        'Confidence': 99,
                                        'Title': '[EMR.3] EMR Cluster security configurations should enforce encryption at rest for EMRFS',
                                        'Description': 'EMR Cluster ' + clusterName + ' has a security configuration specified that does not enforce encryption at rest for EMRFS. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'EMR cluster security configurations cannot be specified after creation. For information on encryption at rest for EMRFS refer to the Encryption at Rest for EMRFS Data in Amazon S3 section of the Amazon EMR Management Guide',
                                                'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-s3'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'AwsEmrCluster',
                                                'Id': clusterArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'clusterId': clusterId,
                                                        'clusterName': clusterName,
                                                        'securityConfigurationName': secConfigName
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 
                                            'Status': 'FAILED',
                                            'RelatedRequirements': [
                                                'NIST CSF PR.DS-1', 
                                                'NIST SP 800-53 MP-8',
                                                'NIST SP 800-53 SC-12',
                                                'NIST SP 800-53 SC-28',
                                                'AICPA TSC CC6.1',
                                                'ISO 27001:2013 A.8.2.3'
                                            ]
                                        },
                                        'Workflow': {
                                            'Status': 'NEW'
                                        },
                                        'RecordState': 'ACTIVE'
                                    }
                                ]
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                    else:
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': clusterArn + '/emr-encryption-at-rest-emrfs-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': clusterArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'INFORMATIONAL' },
                                        'Confidence': 99,
                                        'Title': '[EMR.3] EMR Cluster security configurations should enforce encryption at rest for EMRFS',
                                        'Description': 'EMR Cluster ' + clusterName + ' has a security configuration specified that does not enforce encryption at rest for EMRFS. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'EMR cluster security configurations cannot be specified after creation. For information on encryption at rest for EMRFS refer to the Encryption at Rest for EMRFS Data in Amazon S3 section of the Amazon EMR Management Guide',
                                                'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-s3'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'AwsEmrCluster',
                                                'Id': clusterArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'clusterId': clusterId,
                                                        'clusterName': clusterName,
                                                        'securityConfigurationName': secConfigName
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 
                                            'Status': 'PASSED',
                                            'RelatedRequirements': [
                                                'NIST CSF PR.DS-1', 
                                                'NIST SP 800-53 MP-8',
                                                'NIST SP 800-53 SC-12',
                                                'NIST SP 800-53 SC-28',
                                                'AICPA TSC CC6.1',
                                                'ISO 27001:2013 A.8.2.3'
                                            ]
                                        },
                                        'Workflow': {
                                            'Status': 'RESOLVED'
                                        },
                                        'RecordState': 'ARCHIVED'
                                    }
                                ]
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                except Exception as e:
                    print(e)
            except Exception as e:
                print(e)
        except Exception as e:
            if str(e) == "'SecurityConfiguration'":
                pass
            else:
                print(e)

def emr_security_config_config_ebs_encryption_check():
    for cluster in myEmrClusters:
        clusterId = str(cluster['Id'])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response['Cluster']['Id'])
            clusterName = str(response['Cluster']['Name'])
            clusterArn = str(response['Cluster']['ClusterArn'])
            secConfigName = str(response['Cluster']['SecurityConfiguration'])
            try:
                response = emr.describe_security_configuration(Name=secConfigName)
                configData = str(response['SecurityConfiguration'])
                jsonConfig = json.loads(configData)
                try:
                    ebsEncryptionCheck = str(jsonConfig['EncryptionConfiguration']['AtRestEncryptionConfiguration']['LocalDiskEncryptionConfiguration']['EnableEbsEncryption'])
                    if ebsEncryptionCheck == 'False':
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': clusterArn + '/emr-encryption-at-rest-ebs-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': clusterArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'HIGH' },
                                        'Confidence': 99,
                                        'Title': '[EMR.4] EMR Cluster security configurations should enforce encryption at rest for EBS',
                                        'Description': 'EMR Cluster ' + clusterName + ' has a security configuration specified that does not enforce encryption at rest for EBS. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'EMR cluster security configurations cannot be specified after creation. For information on encryption at rest for EBS refer to the Local Disk Encryption section of the Amazon EMR Management Guide',
                                                'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-localdisk'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'AwsEmrCluster',
                                                'Id': clusterArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'clusterId': clusterId,
                                                        'clusterName': clusterName,
                                                        'securityConfigurationName': secConfigName
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 
                                            'Status': 'FAILED',
                                            'RelatedRequirements': [
                                                'NIST CSF PR.DS-1', 
                                                'NIST SP 800-53 MP-8',
                                                'NIST SP 800-53 SC-12',
                                                'NIST SP 800-53 SC-28',
                                                'AICPA TSC CC6.1',
                                                'ISO 27001:2013 A.8.2.3'
                                            ]
                                        },
                                        'Workflow': {
                                            'Status': 'NEW'
                                        },
                                        'RecordState': 'ACTIVE'
                                    }
                                ]
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                    else:
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': clusterArn + '/emr-encryption-at-rest-ebs-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': clusterArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'INFORMATIONAL' },
                                        'Confidence': 99,
                                        'Title': '[EMR.4] EMR Cluster security configurations should enforce encryption at rest for EBS',
                                        'Description': 'EMR Cluster ' + clusterName + ' has a security configuration specified that enforces encryption at rest for EBS.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'EMR cluster security configurations cannot be specified after creation. For information on encryption at rest for EBS refer to the Local Disk Encryption section of the Amazon EMR Management Guide',
                                                'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-localdisk'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'AwsEmrCluster',
                                                'Id': clusterArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'clusterId': clusterId,
                                                        'clusterName': clusterName,
                                                        'securityConfigurationName': secConfigName
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 
                                            'Status': 'PASSED',
                                            'RelatedRequirements': [
                                                'NIST CSF PR.DS-1', 
                                                'NIST SP 800-53 MP-8',
                                                'NIST SP 800-53 SC-12',
                                                'NIST SP 800-53 SC-28',
                                                'AICPA TSC CC6.1',
                                                'ISO 27001:2013 A.8.2.3'
                                            ]
                                        },
                                        'Workflow': {
                                            'Status': 'RESOLVED'
                                        },
                                        'RecordState': 'ARCHIVED'
                                    }
                                ]
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                except Exception as e:
                    if str(e) == "'LocalDiskEncryptionConfiguration'":
                        # this is a failing check of a lesser severity
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': clusterArn + '/emr-encryption-at-rest-ebs-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': clusterArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'MEDIUM' },
                                        'Confidence': 99,
                                        'Title': '[EMR.4] EMR Cluster security configurations should enforce encryption at rest for EBS',
                                        'Description': 'EMR Cluster ' + clusterName + ' has a security configuration that does not have any local disk encryption configured. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'EMR cluster security configurations cannot be specified after creation. For information on encryption at rest for EBS refer to the Local Disk Encryption section of the Amazon EMR Management Guide',
                                                'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html#emr-encryption-localdisk'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'AwsEmrCluster',
                                                'Id': clusterArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'clusterId': clusterId,
                                                        'clusterName': clusterName,
                                                        'securityConfigurationName': secConfigName
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 
                                            'Status': 'FAILED',
                                            'RelatedRequirements': [
                                                'NIST CSF PR.DS-1', 
                                                'NIST SP 800-53 MP-8',
                                                'NIST SP 800-53 SC-12',
                                                'NIST SP 800-53 SC-28',
                                                'AICPA TSC CC6.1',
                                                'ISO 27001:2013 A.8.2.3'
                                            ]
                                        },
                                        'Workflow': {
                                            'Status': 'NEW'
                                        },
                                        'RecordState': 'ACTIVE'
                                    }
                                ]
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                    else:
                        print(e)
            except Exception as e:
                print(e)
        except Exception as e:
            if str(e) == "'SecurityConfiguration'":
                pass
            else:
                print(e)
            
def emr_security_config_kerberos_check():
    for cluster in myEmrClusters:
        clusterId = str(cluster['Id'])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response['Cluster']['Id'])
            clusterName = str(response['Cluster']['Name'])
            clusterArn = str(response['Cluster']['ClusterArn'])
            secConfigName = str(response['Cluster']['SecurityConfiguration'])
            try:
                response = emr.describe_security_configuration(Name=secConfigName)
                configData = str(response['SecurityConfiguration'])
                jsonConfig = json.loads(configData)
                try:
                    kerbCheck = str(jsonConfig['AuthenticationConfiguration'])
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': clusterArn + '/emr-kerberos-authn-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': clusterArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'INFORMATIONAL' },
                                    'Confidence': 99,
                                    'Title': '[EMR.5] EMR Cluster security configurations should enable Kerberos authentication',
                                    'Description': 'EMR Cluster ' + clusterName + ' has a security configuration specified that does not enable Kerberos authentication. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'EMR cluster security configurations cannot be specified after creation. For information on Kerberized EMR clusters refer to the Use Kerberos Authentication section of the Amazon EMR Management Guide',
                                            'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEmrCluster',
                                            'Id': clusterArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 
                                                    'clusterId': clusterId,
                                                    'clusterName': clusterName,
                                                    'securityConfigurationName': secConfigName,
                                                    'authenticationConfiguration': kerbCheck 
                                                }
                                            }
                                        }
                                    ],
                                    'Compliance': { 
                                        'Status': 'PASSED',
                                        'RelatedRequirements': [
                                            'NIST CSF PR.AC-6',
                                            'NIST SP 800-53 AC-1',
                                            'NIST SP 800-53 AC-2',
                                            'NIST SP 800-53 AC-3',
                                            'NIST SP 800-53 AC-16',
                                            'NIST SP 800-53 AC-19',
                                            'NIST SP 800-53 AC-24',
                                            'NIST SP 800-53 IA-1',
                                            'NIST SP 800-53 IA-2',
                                            'NIST SP 800-53 IA-4',
                                            'NIST SP 800-53 IA-5',
                                            'NIST SP 800-53 IA-8',
                                            'NIST SP 800-53 PE-2',
                                            'NIST SP 800-53 PS-3',
                                            'AICPA TSC CC6.1',
                                            'ISO 27001:2013 A.7.1.1',
                                            'ISO 27001:2013 A.9.2.1'
                                        ]
                                    },
                                    'Workflow': {
                                        'Status': 'RESOLVED'
                                    },
                                    'RecordState': 'ARCHIVED'
                                }
                            ]
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    if str(e) == "'AuthenticationConfiguration'":
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': clusterArn + '/emr-kerberos-authn-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': clusterArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'MEDIUM' },
                                        'Confidence': 99,
                                        'Title': '[EMR.5] EMR Cluster security configurations should enable Kerberos authentication',
                                        'Description': 'EMR Cluster ' + clusterName + ' has a security configuration specified that does not enable Kerberos authentication. Security configurations are used to define encryption, authorization and authentication strategies for your EMR cluster. Clusters cannot be modified after creation, for more information refer to the remediation section.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'EMR cluster security configurations cannot be specified after creation. For information on Kerberized EMR clusters refer to the Use Kerberos Authentication section of the Amazon EMR Management Guide',
                                                'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos.html'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'AwsEmrCluster',
                                                'Id': clusterArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'clusterId': clusterId,
                                                        'clusterName': clusterName,
                                                        'securityConfigurationName': secConfigName
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 
                                            'Status': 'FAILED',
                                            'RelatedRequirements': [
                                                'NIST CSF PR.AC-6',
                                                'NIST SP 800-53 AC-1',
                                                'NIST SP 800-53 AC-2',
                                                'NIST SP 800-53 AC-3',
                                                'NIST SP 800-53 AC-16',
                                                'NIST SP 800-53 AC-19',
                                                'NIST SP 800-53 AC-24',
                                                'NIST SP 800-53 IA-1',
                                                'NIST SP 800-53 IA-2',
                                                'NIST SP 800-53 IA-4',
                                                'NIST SP 800-53 IA-5',
                                                'NIST SP 800-53 IA-8',
                                                'NIST SP 800-53 PE-2',
                                                'NIST SP 800-53 PS-3',
                                                'AICPA TSC CC6.1',
                                                'ISO 27001:2013 A.7.1.1',
                                                'ISO 27001:2013 A.9.2.1'
                                            ]
                                        },
                                        'Workflow': {
                                            'Status': 'NEW'
                                        },
                                        'RecordState': 'ACTIVE'
                                    }
                                ]
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                    else:
                        print(e)
            except Exception as e:
                print(e)
        except Exception as e:
            if str(e) == "'SecurityConfiguration'":
                pass
            else:
                print(e)
            
def emr_cluster_termination_protection_check():
    for cluster in myEmrClusters:
        clusterId = str(cluster['Id'])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response['Cluster']['Id'])
            clusterName = str(response['Cluster']['Name'])
            clusterArn = str(response['Cluster']['ClusterArn'])
            delProtectCheck = str(response['Cluster']['TerminationProtected'])
            if delProtectCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterArn + '/emr-termination-protection-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'LOW' },
                                'Confidence': 99,
                                'Title': '[EMR.6] EMR Clusters should have termination protection enabled',
                                'Description': 'EMR Cluster ' + clusterName + ' does not have termination protection enabled. When termination protection is enabled on a long-running cluster, you can still terminate the cluster, but you must explicitly remove termination protection from the cluster first. This helps ensure that EC2 instances are not shut down by an accident or error. If this configuration is not intentional refer to the remediation section.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For information on EMR termination protection refer to the Using Termination Protection section of the Amazon EMR Management Guide',
                                        'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/UsingEMR_TerminationProtection.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEmrCluster',
                                        'Id': clusterArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'clusterId': clusterId,
                                                'clusterName': clusterName
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'FAILED',
                                    'RelatedRequirements': [
                                        'NIST CSF ID.BE-5', 
                                        'NIST CSF PR.PT-5',
                                        'NIST SP 800-53 CP-2',
                                        'NIST SP 800-53 CP-11',
                                        'NIST SP 800-53 SA-13',
                                        'NIST SP 800-53 SA14',
                                        'AICPA TSC CC3.1',
                                        'AICPA TSC A1.2',
                                        'ISO 27001:2013 A.11.1.4',
                                        'ISO 27001:2013 A.17.1.1',
                                        'ISO 27001:2013 A.17.1.2',
                                        'ISO 27001:2013 A.17.2.1'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'NEW'
                                },
                                'RecordState': 'ACTIVE'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
            else:
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterArn + '/emr-termination-protection-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[EMR.6] EMR Clusters should have termination protection enabled',
                                'Description': 'EMR Cluster ' + clusterName + ' has termination protection enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For information on EMR termination protection refer to the Using Termination Protection section of the Amazon EMR Management Guide',
                                        'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/UsingEMR_TerminationProtection.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEmrCluster',
                                        'Id': clusterArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'clusterId': clusterId,
                                                'clusterName': clusterName
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'PASSED',
                                    'RelatedRequirements': [
                                        'NIST CSF ID.BE-5', 
                                        'NIST CSF PR.PT-5',
                                        'NIST SP 800-53 CP-2',
                                        'NIST SP 800-53 CP-11',
                                        'NIST SP 800-53 SA-13',
                                        'NIST SP 800-53 SA14',
                                        'AICPA TSC CC3.1',
                                        'AICPA TSC A1.2',
                                        'ISO 27001:2013 A.11.1.4',
                                        'ISO 27001:2013 A.17.1.1',
                                        'ISO 27001:2013 A.17.1.2',
                                        'ISO 27001:2013 A.17.2.1'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'RESOLVED'
                                },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)
            
def emr_cluster_logging_check():
    for cluster in myEmrClusters:
        clusterId = str(cluster['Id'])
        try:
            response = emr.describe_cluster(ClusterId=clusterId)
            clusterId = str(response['Cluster']['Id'])
            clusterName = str(response['Cluster']['Name'])
            clusterArn = str(response['Cluster']['ClusterArn'])
            logUriCheck = str(response['Cluster']['LogUri'])
            # this is a passing check
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/emr-cluster-logging-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[EMR.7] EMR Clusters should have logging enabled',
                            'Description': 'EMR Cluster ' + clusterName + ' does has logging enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on EMR cluster logging and debugging refer to the Configure Cluster Logging and Debugging section of the Amazon EMR Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-debugging.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEmrCluster',
                                    'Id': clusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 
                                            'clusterId': clusterId,
                                            'clusterName': clusterName,
                                            'logPathUri': logUriCheck
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF DE.AE-3',
                                    'NIST SP 800-53 AU-6',
                                    'NIST SP 800-53 CA-7',
                                    'NIST SP 800-53 IR-4',
                                    'NIST SP 800-53 IR-5',
                                    'NIST SP 800-53 IR-8', 
                                    'NIST SP 800-53 SI-4',
                                    'AICPA TSC CC7.2',
                                    'ISO 27001:2013 A.12.4.1',
                                    'ISO 27001:2013 A.16.1.7'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        except Exception as e:
            if str(e) == "'LogUri'":
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterArn + '/emr-cluster-logging-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'LOW' },
                                'Confidence': 99,
                                'Title': '[EMR.7] EMR Clusters should have logging enabled',
                                'Description': 'EMR Cluster ' + clusterName + ' does not have logging enabled. You do not need to enable anything to have log files written on the master node. This is the default behavior of Amazon EMR and Hadoop, but can be turned off on creation. If this configuration is not intentional refer to the remediation section.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For information on EMR cluster logging and debugging refer to the Configure Cluster Logging and Debugging section of the Amazon EMR Management Guide',
                                        'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-debugging.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEmrCluster',
                                        'Id': clusterArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'clusterId': clusterId,
                                                'clusterName': clusterName
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'FAILED',
                                    'RelatedRequirements': [
                                        'NIST CSF DE.AE-3',
                                        'NIST SP 800-53 AU-6',
                                        'NIST SP 800-53 CA-7',
                                        'NIST SP 800-53 IR-4',
                                        'NIST SP 800-53 IR-5',
                                        'NIST SP 800-53 IR-8', 
                                        'NIST SP 800-53 SI-4',
                                        'AICPA TSC CC7.2',
                                        'ISO 27001:2013 A.12.4.1',
                                        'ISO 27001:2013 A.16.1.7'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'NEW'
                                },
                                'RecordState': 'ACTIVE'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
            else:
                print(e)

def emr_cluster_block_secgroup_check():
    try:
        response = emr.get_block_public_access_configuration()
        blockPubSgCheck = str(response['BlockPublicAccessConfiguration']['BlockPublicSecurityGroupRules'])
        if blockPubSgCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': awsAccountId + '/account-level-emr-block-public-sg-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': awsAccountId + '/' + awsRegion + '/' + 'emr-acct-sg-block',
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'MEDIUM' },
                            'Confidence': 99,
                            'Title': '[EMR.8] EMR account-level public security group access block should be enabled',
                            'Description': 'EMR account-level public security group access block is not enabled for ' + awsAccountId + ' in AWS region ' + awsRegion + '. Amazon EMR block public access prevents a cluster from launching when any security group associated with the cluster has a rule that allows inbound traffic from IPv4 0.0.0.0/0 or IPv6 ::/0 (public access) on a port, unless the port has been specified as an exception. Port 22 is an exception by default. This is the default behavior of Amazon EMR and Hadoop, but can be turned off on creation. If this configuration is not intentional refer to the remediation section.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on EMR Block Public Access refer to the Using Amazon EMR Block Public Access section of the Amazon EMR Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-block-public-access.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsAccount',
                                    'Id': 'AWS::::Account:' + awsAccountId,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.AC-3',
                                    'NIST SP 800-53 AC-1',
                                    'NIST SP 800-53 AC-17',
                                    'NIST SP 800-53 AC-19',
                                    'NIST SP 800-53 AC-20',
                                    'NIST SP 800-53 SC-15',
                                    'AICPA TSC CC6.6',
                                    'ISO 27001:2013 A.6.2.1',
                                    'ISO 27001:2013 A.6.2.2',
                                    'ISO 27001:2013 A.11.2.6',
                                    'ISO 27001:2013 A.13.1.1',
                                    'ISO 27001:2013 A.13.2.1'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': awsAccountId + '/account-level-emr-block-public-sg-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': awsAccountId + '/' + awsRegion + '/' + 'emr-acct-sg-block',
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[EMR.8] EMR account-level public security group access block should be enabled',
                            'Description': 'EMR account-level public security group access block is not enabled for ' + awsAccountId + ' in AWS region ' + awsRegion + '. Amazon EMR block public access prevents a cluster from launching when any security group associated with the cluster has a rule that allows inbound traffic from IPv4 0.0.0.0/0 or IPv6 ::/0 (public access) on a port, unless the port has been specified as an exception. Port 22 is an exception by default. This is the default behavior of Amazon EMR and Hadoop, but can be turned off on creation. If this configuration is not intentional refer to the remediation section.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on EMR Block Public Access refer to the Using Amazon EMR Block Public Access section of the Amazon EMR Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-block-public-access.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsAccount',
                                    'Id': 'AWS::::Account:' + awsAccountId,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.AC-3',
                                    'NIST SP 800-53 AC-1',
                                    'NIST SP 800-53 AC-17',
                                    'NIST SP 800-53 AC-19',
                                    'NIST SP 800-53 AC-20',
                                    'NIST SP 800-53 SC-15',
                                    'AICPA TSC CC6.6',
                                    'ISO 27001:2013 A.6.2.1',
                                    'ISO 27001:2013 A.6.2.2',
                                    'ISO 27001:2013 A.11.2.6',
                                    'ISO 27001:2013 A.13.1.1',
                                    'ISO 27001:2013 A.13.2.1'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
    except Exception as e:
        print(e)

def emr_auditor():
    emr_cluster_security_configuration_check()
    emr_security_config_encryption_in_transit_check()
    emr_security_config_encryption_at_rest_check()
    emr_security_config_config_ebs_encryption_check()
    emr_security_config_kerberos_check()
    emr_cluster_termination_protection_check()
    emr_cluster_logging_check()
    emr_cluster_block_secgroup_check()

emr_auditor()