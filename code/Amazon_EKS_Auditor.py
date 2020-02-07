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

def public_access_check():
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
                                'Id': clusterArn + '/public-eks-endpoint',
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
                                    'Product Name': 'Docker Compliance Machine Dont Stop'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
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
                print('EKS cluster does not allow public access')
        except Exception as e:
            print(e)

def k8s_latest_check():
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
            if k8sVersionCheck != '1.14':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterArn + '/old-k8s-version',
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
                                    'Product Name': 'Docker Compliance Machine Dont Stop'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
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
                print('EKS cluster is using the latest Kubernetes version')
        except Exception as e:
            print(e)

def eks_auditor():
    public_access_check()
    k8s_latest_check()

eks_auditor()