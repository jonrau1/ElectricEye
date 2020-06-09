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
# import boto3 clients
sts = boto3.client('sts')
redshift = boto3.client('redshift')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through redshift clusters
response = redshift.describe_clusters()
myRedshiftClusters = response['Clusters']

def cluster_public_access_check():
    for cluster in myRedshiftClusters:
        clusterId = str(cluster['ClusterIdentifier'])
        clusterArn = 'arn:aws:redshift:' + awsRegion + ':' + awsAccountId + ':cluster:' + clusterId
        if str(cluster['PubliclyAccessible']) == 'True':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/redshift-public-access-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'CRITICAL' },
                            'Confidence': 99,
                            'Title': '[Redshift.1] Redshift clusters should not be publicly accessible',
                            'Description': 'Redshift cluster ' + clusterId + ' is publicly accessible. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on modifying Redshift public access refer to the Modifying a Cluster section of the Amazon Redshift Cluster Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-console.html#modify-cluster'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRedshiftCluster',
                                    'Id': clusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'ClusterId': clusterId
                                        }
                                    }
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
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/redshift-public-access-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[Redshift.1] Redshift clusters should not be publicly accessible',
                            'Description': 'Redshift cluster ' + clusterId + ' is not publicly accessible.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on modifying Redshift public access refer to the Modifying a Cluster section of the Amazon Redshift Cluster Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-console.html#modify-cluster'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRedshiftCluster',
                                    'Id': clusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'ClusterId': clusterId
                                        }
                                    }
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

def cluster_encryption_check():
    for cluster in myRedshiftClusters:
        clusterId = str(cluster['ClusterIdentifier'])
        clusterArn = 'arn:aws:redshift:' + awsRegion + ':' + awsAccountId + ':cluster:' + clusterId
        if str(cluster['Encrypted']) == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/redshift-cluster-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'HIGH' },
                            'Confidence': 99,
                            'Title': '[Redshift.2] Redshift clusters should be encrypted',
                            'Description': 'Redshift cluster ' + clusterId + ' is not encrypted. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Redshift cluster encryption and how to configure it refer to the Amazon Redshift Database Encryption section of the Amazon Redshift Cluster Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRedshiftCluster',
                                    'Id': clusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'ClusterId': clusterId
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
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/redshift-cluster-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[Redshift.2] Redshift clusters should be encrypted',
                            'Description': 'Redshift cluster ' + clusterId + ' is encrypted.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Redshift cluster encryption and how to configure it refer to the Amazon Redshift Database Encryption section of the Amazon Redshift Cluster Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRedshiftCluster',
                                    'Id': clusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'ClusterId': clusterId
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

def cluster_enhanced_vpc_routing_check():
    for cluster in myRedshiftClusters:
        clusterId = str(cluster['ClusterIdentifier'])
        clusterArn = 'arn:aws:redshift:' + awsRegion + ':' + awsAccountId + ':cluster:' + clusterId
        if str(cluster['EnhancedVpcRouting']) == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/redshift-cluster-enhanced-vpc-routing-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'MEDIUM' },
                            'Confidence': 99,
                            'Title': '[Redshift.3] Redshift clusters should utilize enhanced VPC routing',
                            'Description': 'Redshift cluster ' + clusterId + ' is not utilizing enhanced VPC routing. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Redshift Enhanced VPC routing and how to configure it refer to the Amazon Redshift Enhanced VPC Routing section of the Amazon Redshift Cluster Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/redshift/latest/mgmt/enhanced-vpc-routing.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRedshiftCluster',
                                    'Id': clusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'ClusterId': clusterId
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.AC-5',
                                    'NIST SP 800-53 AC-4',
                                    'NIST SP 800-53 AC-10',
                                    'NIST SP 800-53 SC-7',
                                    'AICPA TSC CC6.1',
                                    'ISO 27001:2013 A.13.1.1',
                                    'ISO 27001:2013 A.13.1.3',
                                    'ISO 27001:2013 A.13.2.1',
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
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/redshift-enhanced-vpc-routing-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[Redshift.3] Redshift clusters should utilize enhanced VPC routing',
                            'Description': 'Redshift cluster ' + clusterId + ' is utilizing enhanced VPC routing.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Redshift Enhanced VPC routing and how to configure it refer to the Amazon Redshift Enhanced VPC Routing section of the Amazon Redshift Cluster Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/redshift/latest/mgmt/enhanced-vpc-routing.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRedshiftCluster',
                                    'Id': clusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'ClusterId': clusterId
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.AC-5',
                                    'NIST SP 800-53 AC-4',
                                    'NIST SP 800-53 AC-10',
                                    'NIST SP 800-53 SC-7',
                                    'AICPA TSC CC6.1',
                                    'ISO 27001:2013 A.13.1.1',
                                    'ISO 27001:2013 A.13.1.3',
                                    'ISO 27001:2013 A.13.2.1',
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

def cluster_logging_check():
    for cluster in myRedshiftClusters:
        clusterId = str(cluster['ClusterIdentifier'])
        clusterArn = 'arn:aws:redshift:' + awsRegion + ':' + awsAccountId + ':cluster:' + clusterId
        response = redshift.describe_logging_status(ClusterIdentifier=clusterId)
        if str(response['LoggingEnabled']) == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/redshift-cluster-logging-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'MEDIUM' },
                            'Confidence': 99,
                            'Title': '[Redshift.4] Redshift clusters should have logging enabled',
                            'Description': 'Redshift cluster ' + clusterId + ' does not have logging enabled. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Redshift logging and how to configure it refer to the Database Audit Logging section of the Amazon Redshift Cluster Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRedshiftCluster',
                                    'Id': clusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'ClusterId': clusterId
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
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/redshift-cluster-logging-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[Redshift.4] Redshift clusters should have logging enabled',
                            'Description': 'Redshift cluster ' + clusterId + ' has logging enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Redshift logging and how to configure it refer to the Database Audit Logging section of the Amazon Redshift Cluster Management Guide',
                                    'Url': 'https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRedshiftCluster',
                                    'Id': clusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'ClusterId': clusterId
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

def redshift_auditor():
    cluster_public_access_check()
    cluster_encryption_check()
    cluster_enhanced_vpc_routing_check()
    cluster_logging_check()

redshift_auditor()