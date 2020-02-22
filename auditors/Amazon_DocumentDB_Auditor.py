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
# find document db instances
response = documentdb.describe_db_instances(
    Filters=[
        {
            'Name': 'engine',
            'Values': [ 'docdb' ]
        }
    ],
    MaxRecords=100
)
myDocDbs = response['DBInstances']

def docdb_public_instance_check():   
    for docdb in myDocDbs:
        docdbId = str(docdb['DBInstanceIdentifier'])
        docdbArn = str(docdb['DBInstanceArn'])
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
                            'Id': docdbArn + '/docdb-public-access',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbArn,
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
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'InstanceId': docdbId }
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
                            'Id': docdbArn + '/docdb-public-access',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbArn,
                            'AwsAccountId': awsAccount,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[DocDb.1] DocumentDB instances should not be exposed to the public',
                            'Description': 'DocumentDB instance ' + docdbId + ' is not exposed to the public.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your DocumentDB is not intended to be public refer to the Connecting to an Amazon DocumentDB Cluster from Outside an Amazon VPC section in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/connect-from-outside-a-vpc.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'InstanceId': docdbId }
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

def docdb_instance_encryption_check():
    for docdb in myDocDbs:
        docdbId = str(docdb['DBInstanceIdentifier'])
        docdbArn = str(docdb['DBInstanceArn'])
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
                            'Id': docdbArn + '/docdb-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbArn,
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
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'InstanceId': docdbId }
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
                            'Id': docdbArn + '/docdb-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbArn,
                            'AwsAccountId': awsAccount,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[DocDb.2] DocumentDB instances should be encrypted',
                            'Description': 'DocumentDB instance ' + docdbId + ' is encrypted.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your DocumentDB is not intended to be unencrypted refer to Encrypting Amazon DocumentDB Data at Rest in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'InstanceId': docdbId }
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

def docdb_instance_audit_logging_check():
    for docdb in myDocDbs:
        docdbId = str(docdb['DBInstanceIdentifier'])
        docdbArn = str(docdb['DBInstanceArn'])
        try:
            # this is a passing check
            logCheck = str(docdb['EnabledCloudwatchLogsExports'])
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': docdbArn + '/docdb-instance-audit-logging-check',
                            'ProductArn': 'arn:docdbArn:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[DocDb.3] DocumentDB instances should have audit logging configured',
                            'Description': 'DocumentDB instance ' + docdbId + ' has audit logging configured.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on DocumentDB audit logging refer to the Auditing Amazon DocumentDB Events section in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'InstanceId': docdbId }
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
        except:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': docdbArn + '/docdb-instance-audit-logging-check',
                            'ProductArn': 'arn:docdbArn:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[DocDb.3] DocumentDB instances should have audit logging configured',
                            'Description': 'DocumentDB instance ' + docdbId + ' does not have audit logging configured. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on DocumentDB audit logging refer to the Auditing Amazon DocumentDB Events section in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'InstanceId': docdbId }
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

def docdb_cluster_multiaz_check():
    # find document db clusters
    response = documentdb.describe_db_clusters(MaxRecords=100)
    myDocDbClusters = response['DBClusters']
    for docdbcluster in myDocDbClusters:
        docdbclusterId = str(docdbcluster['DBClusterIdentifier'])
        docdbClusterArn = str(docdbcluster['DBClusterArn'])
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
                            'Id': docdbClusterArn + '/docdb-cluster-multi-az-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbclusterId,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[DocDb.4] DocumentDB clusters should be configured for Multi-AZ',
                            'Description': 'DocumentDB cluster ' + docdbclusterId + ' is not configured for Multi-AZ. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your DocumentDB cluster should be in Multi-AZ configuration refer to the Understanding Amazon DocumentDB Cluster Fault Tolerance section in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-fault-tolerance.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbClusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'ClusterId': docdbclusterId }
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
                            'Id': docdbClusterArn + '/docdb-cluster-multi-az-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbClusterArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[DocDb.4] DocumentDB clusters should be configured for Multi-AZ',
                            'Description': 'DocumentDB cluster ' + docdbclusterId + ' is configured for Multi-AZ.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your DocumentDB cluster should be in Multi-AZ configuration refer to the Understanding Amazon DocumentDB Cluster Fault Tolerance section in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-fault-tolerance.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbClusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'ClusterId': docdbclusterId }
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

def docdb_cluster_deletion_protection_check():
    # find document db instances
    response = documentdb.describe_db_clusters(MaxRecords=100)
    myDocDbClusters = response['DBClusters']
    for docdbcluster in myDocDbClusters:
        docdbclusterId = str(docdbcluster['DBClusterIdentifier'])
        docdbClusterArn = str(docdbcluster['DBClusterArn'])
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
                            'Id': docdbClusterArn + '/docdb-cluster-deletion-protection-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbClusterArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[DocDb.5] DocumentDB clusters should have deletion protection enabled',
                            'Description': 'DocumentDB cluster ' + docdbclusterId + ' does not have deletion protection enabled. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your DocumentDB cluster should have deletion protection enabled refer to the Deletion Protection section in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-delete.html#db-cluster-deletion-protection'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbClusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'ClusterId': docdbclusterId }
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
                            'Id': docdbClusterArn + '/docdb-cluster-deletion-protection-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': docdbClusterArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[DocDb.5] DocumentDB clusters should have deletion protection enabled',
                            'Description': 'DocumentDB cluster ' + docdbclusterId + ' has deletion protection enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your DocumentDB cluster should have deletion protection enabled refer to the Deletion Protection section in the Amazon DocumentDB Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-delete.html#db-cluster-deletion-protection'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': docdbClusterArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'ClusterId': docdbclusterId }
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

def documentdb_parameter_group_audit_log_check():
    response = documentdb.describe_db_cluster_parameter_groups()
    dbClusterParameters = response['DBClusterParameterGroups']
    for parametergroup in dbClusterParameters:
        if str(parametergroup['DBParameterGroupFamily']) == 'docdb3.6':
            parameterGroupName = str(parametergroup['DBClusterParameterGroupName'])
            parameterGroupArn = str(parametergroup['DBClusterParameterGroupArn'])
            response = documentdb.describe_db_cluster_parameters(DBClusterParameterGroupName=parameterGroupName)
            for parameters in response['Parameters']:
                if str(parameters['ParameterName']) == 'audit_logs':
                    auditLogCheck = str(parameters['ParameterValue'])
                    if auditLogCheck == 'disabled':
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': parameterGroupArn + '/docdb-cluster-parameter-audit-logging-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': parameterGroupArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 40 },
                                        'Confidence': 99,
                                        'Title': '[DocDb.6] DocumentDB cluster parameter groups should enforce audit logging for DocumentDB databases',
                                        'Description': 'DocumentDB cluster parameter group ' + parameterGroupName + ' does not enforce audit logging. Refer to the remediation instructions to remediate this behavior',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'If your DocumentDB cluster should have audit logging enabled refer to the Enabling Auditing section in the Amazon DocumentDB Developer Guide',
                                                'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html#event-auditing-enabling-auditing'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'Other',
                                                'Id': parameterGroupArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 'ParameterGroupName': parameterGroupName }
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
                                        'Id': parameterGroupArn + '/docdb-cluster-parameter-audit-logging-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': parameterGroupArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 0 },
                                        'Confidence': 99,
                                        'Title': '[DocDb.6] DocumentDB cluster parameter groups should enforce audit logging for DocumentDB databases',
                                        'Description': 'DocumentDB cluster parameter group ' + parameterGroupName + ' enforces audit logging.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'If your DocumentDB cluster should have audit logging enabled refer to the Enabling Auditing section in the Amazon DocumentDB Developer Guide',
                                                'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html#event-auditing-enabling-auditing'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'Other',
                                                'Id': parameterGroupArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 'ParameterGroupName': parameterGroupName }
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
                else:
                    pass
        else:
            pass

def documentdb_parameter_group_tls_enforcement_check():
    response = documentdb.describe_db_cluster_parameter_groups()
    dbClusterParameters = response['DBClusterParameterGroups']
    for parametergroup in dbClusterParameters:
        if str(parametergroup['DBParameterGroupFamily']) == 'docdb3.6':
            parameterGroupName = str(parametergroup['DBClusterParameterGroupName'])
            parameterGroupArn = str(parametergroup['DBClusterParameterGroupArn'])
            response = documentdb.describe_db_cluster_parameters(DBClusterParameterGroupName=parameterGroupName)
            for parameters in response['Parameters']:
                if str(parameters['ParameterName']) == 'tls':
                    tlsEnforcementCheck = str(parameters['ParameterValue'])
                    if tlsEnforcementCheck == 'disabled':
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': parameterGroupArn + '/docdb-cluster-parameter-tls-connections-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': parameterGroupArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 60 },
                                        'Confidence': 99,
                                        'Title': '[DocDb.7] DocumentDB cluster parameter groups should enforce TLS connections to DocumentDB databases',
                                        'Description': 'DocumentDB cluster parameter group ' + parameterGroupName + ' does not enforce TLS connections. Refer to the remediation instructions to remediate this behavior',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'If your DocumentDB cluster should have encryption in transit enforced refer to the Managing Amazon DocumentDB Cluster TLS Settings section in the Amazon DocumentDB Developer Guide',
                                                'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.html'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'Other',
                                                'Id': parameterGroupArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 'ParameterGroupName': parameterGroupName }
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
                                        'Id': parameterGroupArn + '/docdb-cluster-parameter-tls-connections-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': parameterGroupArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 0 },
                                        'Confidence': 99,
                                        'Title': '[DocDb.7] DocumentDB cluster parameter groups should enforce TLS connections to DocumentDB databases',
                                        'Description': 'DocumentDB cluster parameter group ' + parameterGroupName + ' enforces TLS connections.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'If your DocumentDB cluster should have encryption in transit enforced refer to the Managing Amazon DocumentDB Cluster TLS Settings section in the Amazon DocumentDB Developer Guide',
                                                'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.html'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'Other',
                                                'Id': parameterGroupArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 'ParameterGroupName': parameterGroupName }
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
                else:
                    pass
        else:
            pass

def documentdb_cluster_snapshot_encryption_check():
    response = documentdb.describe_db_clusters(Filters=[ { 'Name': 'engine','Values': [ 'docdb' ] } ])
    for clusters in response['DBClusters']:
        clusterId = str(clusters['DBClusterIdentifier'])
        response = documentdb.describe_db_cluster_snapshots(DBClusterIdentifier=clusterId)
        for snapshots in response['DBClusterSnapshots']:
            clusterSnapshotId = str(snapshots['DBClusterSnapshotIdentifier'])
            clusterSnapshotArn = str(snapshots['DBClusterSnapshotArn'])
            encryptionCheck = str(snapshots['StorageEncrypted'])
            if encryptionCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterSnapshotArn + '/docdb-cluster-snapshot-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterSnapshotArn,
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
                                'Title': '[DocDb.8] DocumentDB cluster snapshots should be encrypted',
                                'Description': 'DocumentDB cluster snapshot ' + clusterSnapshotId + ' is not encrypted. Refer to the remediation instructions to remediate this behavior',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your DocumentDB cluster snapshot should be encrypted refer to the Limitations for Amazon DocumentDB Encrypted Clusters section in the Amazon DocumentDB Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html#encryption-at-rest-limits'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': clusterSnapshotArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'SnapshotId': clusterSnapshotId }
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
                                'Id': clusterSnapshotArn + '/docdb-cluster-snapshot-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterSnapshotArn,
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
                                'Title': '[DocDb.8] DocumentDB cluster snapshots should be encrypted',
                                'Description': 'DocumentDB cluster snapshot ' + clusterSnapshotId + ' is encrypted.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your DocumentDB cluster snapshot should be encrypted refer to the Limitations for Amazon DocumentDB Encrypted Clusters section in the Amazon DocumentDB Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html#encryption-at-rest-limits'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': clusterSnapshotArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'SnapshotId': clusterSnapshotId }
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

def documentdb_cluster_snapshot_public_share_check():
    response = documentdb.describe_db_clusters(Filters=[ { 'Name': 'engine','Values': [ 'docdb' ] } ])
    for clusters in response['DBClusters']:
        clusterId = str(clusters['DBClusterIdentifier'])
        response = documentdb.describe_db_cluster_snapshots(DBClusterIdentifier=clusterId)
        for snapshots in response['DBClusterSnapshots']:
            clusterSnapshotId = str(snapshots['DBClusterSnapshotIdentifier'])
            clusterSnapshotArn = str(snapshots['DBClusterSnapshotArn'])
            response = documentdb.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=clusterSnapshotId)
            for snapshotattributes in response['DBClusterSnapshotAttributesResult']['DBClusterSnapshotAttributes']:
                if str(snapshotattributes['AttributeName']) == 'restore':
                    valueCheck = str(snapshotattributes['AttributeValues'])
                    if valueCheck == "['all']":
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': clusterSnapshotArn + '/docdb-cluster-snapshot-public-share-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': clusterSnapshotArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [
                                            'Software and Configuration Checks/AWS Security Best Practices',
                                            'Effects/Data Exposure'
                                        ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 90 },
                                        'Confidence': 99,
                                        'Title': '[DocDb.9] DocumentDB cluster snapshots should not be publicly shared',
                                        'Description': 'DocumentDB cluster snapshot ' + clusterSnapshotId + ' is publicly shared. Refer to the remediation instructions to remediate this behavior',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'If your DocumentDB cluster snapshot should not be publicly shared refer to the Sharing Amazon DocumentDB Cluster Snapshots section in the Amazon DocumentDB Developer Guide',
                                                'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/backup-restore.db-cluster-snapshot-share.html'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'Other',
                                                'Id': clusterSnapshotArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 'SnapshotId': clusterSnapshotId }
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
                                        'Id': clusterSnapshotArn + '/docdb-cluster-snapshot-public-share-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': clusterSnapshotArn,
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
                                        'Title': '[DocDb.9] DocumentDB cluster snapshots should not be publicly shared',
                                        'Description': 'DocumentDB cluster snapshot ' + clusterSnapshotId + ' is not publicly shared, however, it may be shared with other accounts. You should periodically review who has snapshots shared with them to ensure they are still authorized',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'If your DocumentDB cluster snapshot should not be publicly shared refer to the Sharing Amazon DocumentDB Cluster Snapshots section in the Amazon DocumentDB Developer Guide',
                                                'Url': 'https://docs.aws.amazon.com/documentdb/latest/developerguide/backup-restore.db-cluster-snapshot-share.html'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'Other',
                                                'Id': clusterSnapshotArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 'SnapshotId': clusterSnapshotId }
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
                else:
                    pass

def documentdb_auditor():
    docdb_public_instance_check()
    docdb_instance_encryption_check()
    docdb_instance_audit_logging_check()
    docdb_cluster_multiaz_check()
    docdb_cluster_deletion_protection_check()
    documentdb_parameter_group_audit_log_check()
    documentdb_parameter_group_tls_enforcement_check()
    documentdb_cluster_snapshot_encryption_check()
    documentdb_cluster_snapshot_public_share_check()

documentdb_auditor()