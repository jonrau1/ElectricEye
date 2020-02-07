import boto3
import os
import datetime
# import boto3 clients
sts = boto3.client('sts')
kafka = boto3.client('kafka')
securityhub = boto3.client('securityhub')
# create env vars for account and region
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through managed kafka clusters
response = kafka.list_clusters()
myMskClusters = response['ClusterInfoList']

def inter_cluster_encryption_in_transit_check():
    for clusters in myMskClusters:
        clusterArn = str(clusters['ClusterArn'])
        clusterName = str(clusters['ClusterName'])
        interClusterEITCheck = str(clusters['EncryptionInfo']['EncryptionInTransit']['InCluster'])
        if interClusterEITCheck != 'True':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/intercluster-encryption-in-transit',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 80 },
                            'Confidence': 99,
                            'Title': '[MSK.1] Managed Kafka Stream clusters should have inter-cluster encryption in transit enabled',
                            'Description': 'MSK cluster ' + clusterName + ' does not have inter-cluster encryption in transit enabled. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your cluster should have inter-cluster encryption in transit enabled refer to the How Do I Get Started with Encryption? section of the Amazon Managed Streaming for Apache Kakfa Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/msk/latest/developerguide/msk-working-with-encryption.html'
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
            print('Inter-cluster encryption in transit is enabled for this cluster')
        
def client_broker_encryption_in_transit_check():
    for clusters in myMskClusters:
        clusterArn = str(clusters['ClusterArn'])
        clusterName = str(clusters['ClusterName'])
        clientBrokerTlsCheck = str(clusters['EncryptionInfo']['EncryptionInTransit']['ClientBroker'])
        if clientBrokerTlsCheck != 'TLS':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/client-broker-tls',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 80 },
                            'Confidence': 99,
                            'Title': '[MSK.2] Managed Kafka Stream clusters should enforce TLS-only communications between clients and brokers',
                            'Description': 'MSK cluster ' + clusterName + ' does not enforce TLS-only communications between clients and brokers. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your cluster should enforce TLS-only communications between clients and brokers refer to the How Do I Get Started with Encryption? section of the Amazon Managed Streaming for Apache Kakfa Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/msk/latest/developerguide/msk-working-with-encryption.html'
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
            print('Inter-cluster encryption in transit is enabled for this cluster')
            
def client_authentication_check():
    for clusters in myMskClusters:
        clusterArn = str(clusters['ClusterArn'])
        clusterName = str(clusters['ClusterName'])
        try:
            clientAuthCheck = str(clusters['ClientAuthentication']['Tls']['CertificateAuthorityArnList'])
            print(clientAuthCheck)
        except:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/tls-client-auth',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[MSK.3] Managed Kafka Stream clusters should use TLS for client authentication',
                            'Description': 'MSK cluster ' + clusterName + ' does not use TLS for client authentication. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your cluster should use TLS for client authentication refer to the Client Authentication section of the Amazon Managed Streaming for Apache Kakfa Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html'
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
            print('Private CA TLS auth is enabled for this cluster')
            
def cluster_enhanced_monitoring_check():
    for clusters in myMskClusters:
        clusterArn = str(clusters['ClusterArn'])
        clusterName = str(clusters['ClusterName'])
        enhancedMonitoringCheck = str(clusters['EnhancedMonitoring'])
        if enhancedMonitoringCheck == 'DEFAULT':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clusterArn + '/detailed-monitoring',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clusterArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[MSK.4] Managed Kafka Stream clusters should use enhanced monitoring',
                            'Description': 'MSK cluster ' + clusterName + ' does not use enhanced monitoring. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your cluster should use enhanced monitoring refer to the Monitoring an Amazon MSK Cluster section of the Amazon Managed Streaming for Apache Kakfa Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/msk/latest/developerguide/monitoring.html'
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
            print('Enhanced monitoring is enabled for this cluster')
        
def msk_auditor():
    inter_cluster_encryption_in_transit_check()
    client_broker_encryption_in_transit_check()
    cluster_enhanced_monitoring_check()
    client_authentication_check()
    
msk_auditor()