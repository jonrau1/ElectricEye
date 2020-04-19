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
elasticache = boto3.client('elasticache')
securityhub = boto3.client('securityhub')
# create env vars for account and region
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']

def redis_auth_check():
    # loop through EC clusters
    response = elasticache.describe_cache_clusters(MaxRecords=100)
    myElasticacheClusters = response['CacheClusters']
    for clusters in myElasticacheClusters:
        clusterId = str(clusters['CacheClusterId'])
        clusterEngine = str(clusters['Engine'])
        # ignore memcached clusters
        if clusterEngine != 'redis':
            print('Memcached cluster found, skipping as it does not support encryption')
            pass
        else:
            engineVersion = str(clusters['EngineVersion'])
            # check for auth token
            authTokenCheck = str(clusters['AuthTokenEnabled'])
            if authTokenCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterId + '/no-redis-auth-token',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterId,
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
                                'Title': '[Elasticache.Redis.1] Elasticache Redis clusters should have an AUTH token enabled',
                                'Description': 'Elasticache cluster ' + clusterId + ' does not have a Redis AUTH token enabled. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your cluster should have a Redis AUTH token refer to the Modifying the AUTH Token on an Existing ElastiCache for Redis Cluster section of the ElastiCache for Redis User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html#auth-modifyng-token'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsElastiCacheCacheCluster',
                                        'Id': 'arn:aws:elasticache:' + awsRegion + ':' + awsAccountId + ':cluster:' + clusterId,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'ClusterId': clusterId, 'EngineVersion': engineVersion }
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
                                'Id': clusterId + '/no-redis-auth-token',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterId,
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
                                'Title': '[Elasticache.Redis.1] Elasticache Redis clusters should have an AUTH token enabled',
                                'Description': 'Elasticache cluster ' + clusterId + ' has a Redis AUTH token enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your cluster should have a Redis AUTH token refer to the Modifying the AUTH Token on an Existing ElastiCache for Redis Cluster section of the ElastiCache for Redis User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html#auth-modifyng-token'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsElastiCacheCacheCluster',
                                        'Id': 'arn:aws:elasticache:' + awsRegion + ':' + awsAccountId + ':cluster:' + clusterId,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'ClusterId': clusterId, 'EngineVersion': engineVersion }
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

def encryption_at_rest_check():
    # loop through EC clusters
    response = elasticache.describe_cache_clusters(MaxRecords=100)
    myElasticacheClusters = response['CacheClusters']
    for clusters in myElasticacheClusters:
        clusterId = str(clusters['CacheClusterId'])
        clusterEngine = str(clusters['Engine'])
        # ignore memcached clusters
        if clusterEngine != 'redis':
            print('Memcached cluster found, skipping as it does not support encryption')
            pass
        else:
            engineVersion = str(clusters['EngineVersion'])
            # check for encryption at rest
            atRestEncryptionCheck = str(clusters['AtRestEncryptionEnabled'])
            if atRestEncryptionCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterId + '/no-redis-auth-token',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterId,
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
                                'Title': '[Elasticache.Redis.2] Elasticache Redis clusters should have encryption at rest enabled',
                                'Description': 'Elasticache cluster ' + clusterId + ' does not have encryption at rest enabled. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your cluster should have encryption at rest enabled refer to the At-Rest Encryption in ElastiCache for Redis section of the ElastiCache for Redis User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html#at-rest-encryption-enable'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsElastiCacheCacheCluster',
                                        'Id': 'arn:aws:elasticache:' + awsRegion + ':' + awsAccountId + ':cluster:' + clusterId,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'ClusterId': clusterId, 'EngineVersion': engineVersion }
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
                                'Id': clusterId + '/no-redis-auth-token',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterId,
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
                                'Title': '[Elasticache.Redis.2] Elasticache Redis clusters should have encryption at rest enabled',
                                'Description': 'Elasticache cluster ' + clusterId + ' has encryption at rest enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your cluster should have encryption at rest enabled refer to the At-Rest Encryption in ElastiCache for Redis section of the ElastiCache for Redis User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html#at-rest-encryption-enable'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsElastiCacheCacheCluster',
                                        'Id': 'arn:aws:elasticache:' + awsRegion + ':' + awsAccountId + ':cluster:' + clusterId,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'ClusterId': clusterId, 'EngineVersion': engineVersion }
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

def encryption_in_transit_check():
    # loop through EC clusters
    response = elasticache.describe_cache_clusters(MaxRecords=100)
    myElasticacheClusters = response['CacheClusters']
    for clusters in myElasticacheClusters:
        clusterId = str(clusters['CacheClusterId'])
        clusterEngine = str(clusters['Engine'])
        # ignore memcached clusters
        if clusterEngine != 'redis':
            print('Memcached cluster found, skipping as it does not support encryption')
            pass
        else:
            engineVersion = str(clusters['EngineVersion'])
            # check for encryption in transit
            inTransitEncryptionCheck = str(clusters['TransitEncryptionEnabled'])
            if inTransitEncryptionCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clusterId + '/no-redis-auth-token',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterId,
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
                                'Title': '[Elasticache.Redis.3] Elasticache Redis clusters should have encryption in transit enabled',
                                'Description': 'Elasticache cluster ' + clusterId + ' does not have encryption in transit enabled. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your cluster should have encryption in transit enabled refer to the Enabling In-Transit Encryption section of the ElastiCache for Redis User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html#in-transit-encryption-enable'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsElastiCacheCacheCluster',
                                        'Id': 'arn:aws:elasticache:' + awsRegion + ':' + awsAccountId + ':cluster:' + clusterId,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'ClusterId': clusterId, 'EngineVersion': engineVersion }
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
                                'Id': clusterId + '/no-redis-auth-token',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clusterId,
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
                                'Title': '[Elasticache.Redis.3] Elasticache Redis clusters should have encryption in transit enabled',
                                'Description': 'Elasticache cluster ' + clusterId + ' has encryption in transit enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your cluster should have encryption in transit enabled refer to the Enabling In-Transit Encryption section of the ElastiCache for Redis User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html#in-transit-encryption-enable'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsElastiCacheCacheCluster',
                                        'Id': 'arn:aws:elasticache:' + awsRegion + ':' + awsAccountId + ':cluster:' + clusterId,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'ClusterId': clusterId, 'EngineVersion': engineVersion }
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

def elasticache_redis_auditor():
    redis_auth_check()
    encryption_at_rest_check()
    encryption_in_transit_check()

elasticache_redis_auditor()