import boto3
import datetime
import os
# import boto3 clients
securityhub = boto3.client('securityhub')
documentdb = boto3.client('docdb')
sts = boto3.client('sts')
# create account id & region variables
awsAccount = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']

def public_instance_check():
    # find document db instances
    response = documentdb.describe_db_instances(MaxRecords=100)
    myDocDbs = response['DBInstances']
    for docdb in myDocDbs:
        docdbId = str(docdb['DBInstanceIdentifier'])
        publicAccessCheck = str(docdb['PubliclyAccessible'])
        if publicAccessCheck == 'True':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': docdbId + '/public-access',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbId,
                            'AwsAccountId': awsAccount,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 80 },
                            'Confidence': 99,
                            'Title': '[DocDb.1] DocumentDB instances should not be exposed to the public',
                            'Description': 'DocumentDB instance ' + docdbId + ' is exposed to the public. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your DocumentDB is not intended to be public refer to the Connecting to an Amazon DocumentDB Cluster from Outside an Amazon VPC section in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/connect-from-outside-a-vpc.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'Docker Compliance Machine Dont Stop'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbId,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'DocumentDB Instance': docdbId }
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
            print('DocumentDB instance is not public')

def instance_encryption_check():
    # find document db instances
    response = documentdb.describe_db_instances(MaxRecords=100)
    myDocDbs = response['DBInstances']
    for docdb in myDocDbs:
        docdbId = str(docdb['DBInstanceIdentifier'])
        encryptionCheck = str(docdb['StorageEncrypted'])
        if encryptionCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': docdbId + '/public-access',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbId,
                            'AwsAccountId': awsAccount,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 80 },
                            'Confidence': 99,
                            'Title': '[DocDb.2] DocumentDB instances should be encrypted',
                            'Description': 'DocumentDB instance ' + docdbId + ' is not encrypted. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your DocumentDB is not intended to be unencrypted refer to Encrypting Amazon DocumentDB Data at Rest in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'Docker Compliance Machine Dont Stop'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbId,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'DocumentDB Instance': docdbId }
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
            print('DocumentDB instance is encrypted')

def cluster_multiaz_check():
    # find document db instances
    response = documentdb.describe_db_clusters(MaxRecords=100)
    myDocDbClusters = response['DBClusters']
    for docdbcluster in myDocDbClusters:
        docdbId = str(docdbcluster['DBClusterIdentifier'])
        multiAzCheck = str(docdbcluster['MultiAZ'])
        if multiAzCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': docdbId + '/multi-az',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbId,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[DocDb.3] DocumentDB clusters should be configured for Multi-AZ',
                            'Description': 'DocumentDB cluster ' + docdbId + ' is not configured for Multi-AZ. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your DocumentDB cluster should be in Multi-AZ configuration refer to the Understanding Amazon DocumentDB Cluster Fault Tolerance section in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-fault-tolerance.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'Docker Compliance Machine Dont Stop'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbId,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'DocumentDB Cluster': docdbId }
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
            print('DocumentDB cluster is configured for HA')

def cluster_deletion_protection_check():
    # find document db instances
    response = documentdb.describe_db_clusters(MaxRecords=100)
    myDocDbClusters = response['DBClusters']
    for docdbcluster in myDocDbClusters:
        docdbId = str(docdbcluster['DBClusterIdentifier'])
        multiAzCheck = str(docdbcluster['MultiAZ'])
        if multiAzCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': docdbId + '/multi-az',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbId,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[DocDb.4] DocumentDB clusters should have deletion protection enabled',
                            'Description': 'DocumentDB cluster ' + docdbId + ' does not have deletion protection enabled. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your DocumentDB cluster should have deletion protection enabled refer to the Deletion Protection section in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-delete.html#db-cluster-deletion-protection'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'Docker Compliance Machine Dont Stop'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbId,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'DocumentDB Cluster': docdbId }
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
            print('DocumentDB cluster is configured for HA')

def documentdb_auditor():
    public_instance_check()
    instance_encryption_check()
    cluster_multiaz_check()
    cluster_deletion_protection_check()

documentdb_auditor()