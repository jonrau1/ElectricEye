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
elasticsearch = boto3.client('es')
securityhub = boto3.client('securityhub')
# create env vars for account and region
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through all elasticsearch domains
response = elasticsearch.list_domain_names()
myDomainNames = response['DomainNames']
    
def dedicated_master_check():    
    for domains in myDomainNames:
        esDomainName = str(domains['DomainName'])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response['DomainStatus']['ElasticsearchVersion'])
        domainId = str(response['DomainStatus']['DomainId'])
        domainArn = str(response['DomainStatus']['ARN'])
        dedicatedMasterCheck = str(response['DomainStatus']['ElasticsearchClusterConfig']['DedicatedMasterEnabled'])
        if dedicatedMasterCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': domainArn + '/elasticsearch-dedicated-master-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[Elasticsearch.1] Elasticsearch Service domains should use dedicated master nodes',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' does not use dedicated master nodes. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your domain should dedicated master nodes enabled refer to the Configuring Amazon ES Domains section of the Amazon Elasticsearch Service Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomains-configure-cluster'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion
                                        }
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
                            'Id': domainArn + '/elasticsearch-dedicated-master-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Elasticsearch.1] Elasticsearch Service domains should use dedicated master nodes',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' uses dedicated master nodes.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your domain should dedicated master nodes enabled refer to the Configuring Amazon ES Domains section of the Amazon Elasticsearch Service Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomains-configure-cluster'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion
                                        }
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
        
def cognito_check():
    for domains in myDomainNames:
        esDomainName = str(domains['DomainName'])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response['DomainStatus']['ElasticsearchVersion'])
        domainId = str(response['DomainStatus']['DomainId'])
        domainArn = str(response['DomainStatus']['ARN'])
        cognitoEnabledCheck = str(response['DomainStatus']['CognitoOptions']['Enabled'])
        if cognitoEnabledCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': domainArn + '/elasticsearch-cognito-auth-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 50 },
                            'Confidence': 99,
                            'Title': '[Elasticsearch.2] Elasticsearch Service domains should use Cognito authentication for Kibana',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' does not use Cognito authentication for Kibana. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your domain should use Cognito authentication for Kibana refer to the Amazon Cognito Authentication for Kibana section of the Amazon Elasticsearch Service Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion
                                        }
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
                            'Id': domainArn + '/elasticsearch-cognito-auth-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Elasticsearch.2] Elasticsearch Service domains should use Cognito authentication for Kibana',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' uses Cognito authentication for Kibana.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your domain should use Cognito authentication for Kibana refer to the Amazon Cognito Authentication for Kibana section of the Amazon Elasticsearch Service Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion
                                        }
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
    for domains in myDomainNames:
        esDomainName = str(domains['DomainName'])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response['DomainStatus']['ElasticsearchVersion'])
        domainId = str(response['DomainStatus']['DomainId'])
        domainArn = str(response['DomainStatus']['ARN'])
        encryptionAtRestCheck = str(response['DomainStatus']['EncryptionAtRestOptions']['Enabled'])
        if encryptionAtRestCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': domainArn + '/elasticsearch-encryption-at-rest-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
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
                            'Title': '[Elasticsearch.3] Elasticsearch Service domains should be encrypted at rest',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' is not encrypted at rest. You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 5.1 or later',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 5.1 or later.',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html#enabling-ear'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion,
                                            'EncryptionAtRestOptions': { 'Enabled': False }
                                        }
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
                            'Id': domainArn + '/elasticsearch-encryption-at-rest-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
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
                            'Title': '[Elasticsearch.3] Elasticsearch Service domains should be encrypted at rest',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' is encrypted at rest',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 5.1 or later.',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html#enabling-ear'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion,
                                            'EncryptionAtRestOptions': { 'Enabled': True }
                                        }
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

def node2node_encryption_check():
    for domains in myDomainNames:
        esDomainName = str(domains['DomainName'])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response['DomainStatus']['ElasticsearchVersion'])
        domainId = str(response['DomainStatus']['DomainId'])
        domainArn = str(response['DomainStatus']['ARN'])
        node2nodeEncryptionCheck = str(response['DomainStatus']['NodeToNodeEncryptionOptions']['Enabled'])
        if node2nodeEncryptionCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': domainArn + '/elasticsearch-node2node-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
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
                            'Title': '[Elasticsearch.4] Elasticsearch Service domains should use node-to-node encryption',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' does not use node-to-node encryption. You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 6.0 or later',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 6.0 or later.',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion,
                                            'NodeToNodeEncryptionOptions': { 'Enabled': False }
                                        }
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
                            'Id': domainArn + '/elasticsearch-node2node-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
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
                            'Title': '[Elasticsearch.4] Elasticsearch Service domains should use node-to-node encryption',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' uses node-to-node encryption.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 6.0 or later.',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion,
                                            'NodeToNodeEncryptionOptions': { 'Enabled': True }
                                        }
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

def https_enforcement_check():
    for domains in myDomainNames:
        esDomainName = str(domains['DomainName'])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response['DomainStatus']['ElasticsearchVersion'])
        domainId = str(response['DomainStatus']['DomainId'])
        domainArn = str(response['DomainStatus']['ARN'])
        httpsEnforcementCheck = str(response['DomainStatus']['DomainEndpointOptions']['EnforceHTTPS'])
        if httpsEnforcementCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': domainArn + '/elasticsearch-enforce-https-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
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
                            'Title': '[Elasticsearch.5] Elasticsearch Service domains should enforce HTTPS-only communications',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' does not enforce HTTPS-only communications. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your domain should enforce HTTPS-only communications refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion,
                                            'DomainEndpointOptions': { 'EnforceHTTPS': False }
                                        }
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
                            'Id': domainArn + '/elasticsearch-enforce-https-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
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
                            'Title': '[Elasticsearch.5] Elasticsearch Service domains should enforce HTTPS-only communications',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' enforces HTTPS-only communications. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your domain should enforce HTTPS-only communications refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion,
                                            'DomainEndpointOptions': { 'EnforceHTTPS': True }
                                        }
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

def tls_policy_check():
    for domains in myDomainNames:
        esDomainName = str(domains['DomainName'])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response['DomainStatus']['ElasticsearchVersion'])
        domainId = str(response['DomainStatus']['DomainId'])
        domainArn = str(response['DomainStatus']['ARN'])
        httpsEnforcementCheck = str(response['DomainStatus']['DomainEndpointOptions']['EnforceHTTPS'])
        if httpsEnforcementCheck == 'True':
            tlsPolicyCheck = str(response['DomainStatus']['DomainEndpointOptions']['TLSSecurityPolicy'])
            if tlsPolicyCheck != 'Policy-Min-TLS-1-2-2019-07':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': domainArn + '/elasticsearch-tls-1-2-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': domainArn,
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
                                'Title': '[Elasticsearch.6] Elasticsearch Service domains that enforce HTTPS-only communications should use a TLS 1.2 security policy',
                                'Description': 'Elasticsearch Service domain ' + esDomainName + ' does not use a TLS 1.2 security policy. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your domain should use a TLS 1.2 security policy refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsElasticsearchDomain',
                                        'Id': domainArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'AwsElasticsearchDomain': {
                                                'DomainId': domainId,
                                                'DomainName': esDomainName,
                                                'ElasticsearchVersion': esVersion,
                                                'DomainEndpointOptions': {
                                                    'EnforceHTTPS': True,
                                                    'TLSSecurityPolicy': tlsPolicyCheck
                                                }
                                            }
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
                                'Id': domainArn + '/elasticsearch-tls-1-2-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': domainArn,
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
                                'Title': '[Elasticsearch.6] Elasticsearch Service domains that enforce HTTPS-only communications should use a TLS 1.2 security policy',
                                'Description': 'Elasticsearch Service domain ' + esDomainName + ' uses a TLS 1.2 security policy.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your domain should use a TLS 1.2 security policy refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsElasticsearchDomain',
                                        'Id': domainArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'AwsElasticsearchDomain': {
                                                'DomainId': domainId,
                                                'DomainName': esDomainName,
                                                'ElasticsearchVersion': esVersion,
                                                'DomainEndpointOptions': {
                                                    'EnforceHTTPS': True,
                                                    'TLSSecurityPolicy': tlsPolicyCheck
                                                }
                                            }
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
            print('HTTPS Only is not enforced, ignoring this check')
            pass
        
def elastic_update_check():
    for domains in myDomainNames:
        esDomainName = str(domains['DomainName'])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response['DomainStatus']['ElasticsearchVersion'])
        domainId = str(response['DomainStatus']['DomainId'])
        domainArn = str(response['DomainStatus']['ARN'])
        updateCheck = str(response['DomainStatus']['ServiceSoftwareOptions']['UpdateAvailable'])
        updateInformation = str(response['DomainStatus']['ServiceSoftwareOptions']['Description'])
        if updateCheck == 'True':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': domainArn + '/elasticsearch-enforce-https-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[Elasticsearch.7] Elasticsearch Service domains should be updated to the latest service software version',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' is not up to date. Service provided message follows: ' + updateInformation + '. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For update information refer to the Service Software Updates section of the Amazon Elasticsearch Service Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-service-software'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion
                                        }
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
                            'Id': domainArn + '/elasticsearch-enforce-https-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': domainArn,
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
                            'Title': '[Elasticsearch.7] Elasticsearch Service domains should be updated to the latest service software version',
                            'Description': 'Elasticsearch Service domain ' + esDomainName + ' is up to date. Service provided message follows: ' + updateInformation,
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For update information refer to the Service Software Updates section of the Amazon Elasticsearch Service Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-service-software'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsElasticsearchDomain',
                                    'Id': domainArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsElasticsearchDomain': {
                                            'DomainId': domainId,
                                            'DomainName': esDomainName,
                                            'ElasticsearchVersion': esVersion
                                        }
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
        
def elasticsearch_auditor():
    dedicated_master_check()
    cognito_check()
    encryption_at_rest_check()
    node2node_encryption_check()
    https_enforcement_check()
    tls_policy_check()
    elastic_update_check()
    
elasticsearch_auditor()