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
eks = boto3.client('eks')
securityhub = boto3.client('securityhub')
# create region & account variables
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']

def eks_public_endpoint_access_check():
    # loop through EKS clusters
    response = eks.list_clusters(maxResults=100)
    myEksClusters = response['clusters']
    for clusters in myEksClusters:
        cluster = str(clusters)
        try:
            response = eks.describe_cluster(name=cluster)
            clusterName = str(response['cluster']['name'])
            clusterArn = str(response['cluster']['arn'])
            eksPublicAccessCheck = str(response['cluster']['resourcesVpcConfig']['endpointPublicAccess'])
            if eksPublicAccessCheck == 'True':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterArn + '/public-endpoint-access-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterName,
                                'AwsAccountId': awsAccountId,
                                'Types': [
                                    'Software and Configuration Checks/AWS Security Best Practices',
                                    'Effects/Data Exposure'
                                ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 80 },
                                'Confidence': 99,
                                'Title': '[EKS.1] Elastic Kubernetes Service (EKS) cluster API servers should not be accessible from the internet',
                                'Description': 'Elastic Kubernetes Service (EKS) cluster ' + clusterName + ' API server is accessible from the internet. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your EKS cluster is not intended to be public refer to the Amazon EKS Cluster Endpoint Access Control section of the EKS user guide',
                                        'Url': 'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEksCluster',
                                        'Id': clusterArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'Cluster Name': clusterName }
                                        }
                                    }
                                ],
                                'Compliance': { 'Status': 'FAILED' },
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
                                'Id': clusterArn + '/public-endpoint-access-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterName,
                                'AwsAccountId': awsAccountId,
                                'Types': [
                                    'Software and Configuration Checks/AWS Security Best Practices',
                                    'Effects/Data Exposure'
                                ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[EKS.1] Elastic Kubernetes Service (EKS) cluster API servers should not be accessible from the internet',
                                'Description': 'Elastic Kubernetes Service (EKS) cluster ' + clusterName + ' API server is not accessible from the internet.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your EKS cluster is not intended to be public refer to the Amazon EKS Cluster Endpoint Access Control section of the EKS user guide',
                                        'Url': 'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEksCluster',
                                        'Id': clusterArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'Cluster Name': clusterName }
                                        }
                                    }
                                ],
                                'Compliance': { 'Status': 'PASSED' },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

def eks_latest_k8s_version_check():
    # loop through EKS clusters
    response = eks.list_clusters(maxResults=100)
    myEksClusters = response['clusters']
    for clusters in myEksClusters:
        cluster = str(clusters)
        try:
            response = eks.describe_cluster(name=cluster)
            clusterName = str(response['cluster']['name'])
            clusterArn = str(response['cluster']['arn'])
            k8sVersionCheck = str(response['cluster']['version'])
            if k8sVersionCheck != '1.14' or '1.15':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterArn + '/eks-latest-k8s-version-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterName,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices', ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 40 },
                                'Confidence': 99,
                                'Title': '[EKS.2] Elastic Kubernetes Service (EKS) clusters should use the latest Kubernetes version',
                                'Description': 'Elastic Kubernetes Service (EKS) cluster ' + clusterName + ' is using Kubernetes version ' + k8sVersionCheck + '. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'Unless your application requires a specific version of Kubernetes, AWS recommends you choose the latest available Kubernetes version supported by Amazon EKS for your clusters. For upgrade information refer to the Updating an Amazon EKS Cluster Kubernetes Version section of the EKS user guide',
                                        'Url': 'https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEksCluster',
                                        'Id': clusterArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'Cluster Name': clusterName }
                                        }
                                    }
                                ],
                                'Compliance': { 'Status': 'FAILED' },
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
                                'Id': clusterArn + '/eks-latest-k8s-version-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterName,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices', ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[EKS.2] Elastic Kubernetes Service (EKS) clusters should use the latest Kubernetes version',
                                'Description': 'Elastic Kubernetes Service (EKS) cluster ' + clusterName + ' is using Kubernetes version ' + k8sVersionCheck,
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'Unless your application requires a specific version of Kubernetes, AWS recommends you choose the latest available Kubernetes version supported by Amazon EKS for your clusters. For upgrade information refer to the Updating an Amazon EKS Cluster Kubernetes Version section of the EKS user guide',
                                        'Url': 'https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEksCluster',
                                        'Id': clusterArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'Cluster Name': clusterName }
                                        }
                                    }
                                ],
                                'Compliance': { 'Status': 'PASSED' },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

def eks_logging_audit_auth_check():
    # loop through EKS clusters
    response = eks.list_clusters(maxResults=100)
    myEksClusters = response['clusters']
    for clusters in myEksClusters:
        cluster = str(clusters)
        try:
            response = eks.describe_cluster(name=cluster)
            clusterName = str(response['cluster']['name'])
            clusterArn = str(response['cluster']['arn'])
            logInfo =  response['cluster']['logging']['clusterLogging']
            for logs in logInfo:
                logTypes = logs['types']
                enableCheck = str(logs['enabled'])
                if enableCheck == 'True':
                    for logs in logTypes:
                        if str(logs) == 'authenticator' and 'audit':
                            try:
                                # ISO Time
                                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                                # create Sec Hub finding
                                response = securityhub.batch_import_findings(
                                    Findings=[
                                        {
                                            'SchemaVersion': '2018-10-08',
                                            'Id': clusterArn + '/eks-logging-audit-auth-check',
                                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                            'GeneratorId': clusterName,
                                            'AwsAccountId': awsAccountId,
                                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices', ],
                                            'FirstObservedAt': iso8601Time,
                                            'CreatedAt': iso8601Time,
                                            'UpdatedAt': iso8601Time,
                                            'Severity': { 'Normalized': 40 },
                                            'Confidence': 99,
                                            'Title': '[EKS.3] Elastic Kubernetes Service (EKS) clusters should have authenticator and/or audit logging enabled',
                                            'Description': 'Elastic Kubernetes Service (EKS) cluster ' + clusterName + ' does not have authenticator or audit logging enabled. Refer to the remediation instructions if this configuration is not intended',
                                            'Remediation': {
                                                'Recommendation': {
                                                    'Text': 'To enable logging for your cluster refer to the Amazon EKS Control Plane Logging section of the EKS user guide',
                                                    'Url': 'https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html'
                                                }
                                            },
                                            'ProductFields': {
                                                'Product Name': 'ElectricEye'
                                            },
                                            'Resources': [
                                                {
                                                    'Type': 'AwsEksCluster',
                                                    'Id': clusterArn,
                                                    'Partition': 'aws',
                                                    'Region': awsRegion,
                                                    'Details': {
                                                        'Other': { 'Cluster Name': clusterName }
                                                    }
                                                }
                                            ],
                                            'Compliance': { 'Status': 'FAILED' },
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
                                            'Id': clusterArn + '/eks-logging-audit-auth-check',
                                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                            'GeneratorId': clusterName,
                                            'AwsAccountId': awsAccountId,
                                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices', ],
                                            'FirstObservedAt': iso8601Time,
                                            'CreatedAt': iso8601Time,
                                            'UpdatedAt': iso8601Time,
                                            'Severity': { 'Normalized': 40 },
                                            'Confidence': 99,
                                            'Title': '[EKS.3] Elastic Kubernetes Service (EKS) clusters should have authenticator and/or audit logging enabled',
                                            'Description': 'Elastic Kubernetes Service (EKS) cluster ' + clusterName + ' does not have authenticator or audit logging enabled. Refer to the remediation instructions if this configuration is not intended',
                                            'Remediation': {
                                                'Recommendation': {
                                                    'Text': 'To enable logging for your cluster refer to the Amazon EKS Control Plane Logging section of the EKS user guide',
                                                    'Url': 'https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html'
                                                }
                                            },
                                            'ProductFields': {
                                                'Product Name': 'ElectricEye'
                                            },
                                            'Resources': [
                                                {
                                                    'Type': 'AwsEksCluster',
                                                    'Id': clusterArn,
                                                    'Partition': 'aws',
                                                    'Region': awsRegion,
                                                    'Details': {
                                                        'Other': { 'Cluster Name': clusterName }
                                                    }
                                                }
                                            ],
                                            'Compliance': { 'Status': 'FAILED' },
                                            'RecordState': 'ACTIVE'
                                        }
                                    ]
                                )
                                print(response)
                            except Exception as e:
                                print(e)
        except Exception as e:
            print(e)

def eks_auditor():
    eks_public_endpoint_access_check()
    eks_latest_k8s_version_check()
    eks_logging_audit_auth_check()

eks_auditor()