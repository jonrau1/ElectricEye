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
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
dynamodb = boto3.client('dynamodb')
# loop through DynamoDB tables
def paginate(cache):
    response = cache.get("paginate")
    if response:
        return response
    get_paginators = dynamodb.get_paginator('list_tables')
    if get_paginators:
        cache["paginate"] = get_paginators.paginate()
        return cache["paginate"]

@registry.register_check("dynamodb")
def ddb_kms_cmk_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DynamoDB.1] DynamoDB tables should use KMS CMKs for encryption at rest"""
    iterator = paginate(cache=cache)
    for page in iterator:
        for table in page['TableNames']:
            tableName = str(table)
            tableArn = dynamodb.describe_table(TableName=tableName)['Table']['TableArn']
            try:
                response = dynamodb.describe_table(TableName=tableName)
                kmsCheck = str(response['Table']['SSEDescription']['SSEType'])
                if kmsCheck != 'KMS':
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    finding={
                        'SchemaVersion': '2018-10-08',
                        'Id': tableArn + '/ddb-kms-cmk-check',
                        'ProductArn': f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        'GeneratorId': tableArn,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'MEDIUM' },
                        'Confidence': 99,
                        'Title': '[DynamoDB.1] DynamoDB tables should use KMS CMKs for encryption at rest',
                        'Description': 'DynamoDB table ' + tableName + ' is not using a KMS CMK for encryption. Refer to the remediation instructions if this configuration is not intended',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'When you access an encrypted table, DynamoDB decrypts the table data transparently. You can switch between the AWS owned CMK, AWS managed CMK, and customer managed CMK at any given time. For more information refer to the DynamoDB Encryption at Rest section of the Amazon DynamoDB Developer Guide',
                                'Url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'AwsDynamoDbTable',
                                'Id': tableArn,
                                
                                'Partition': awsPartition,
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 'tableName': tableName }
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
                    yield finding
                else:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    finding={
                        'SchemaVersion': '2018-10-08',
                        'Id': tableArn + '/ddb-kms-cmk-check',
                        'ProductArn': f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        'GeneratorId': tableArn,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'INFORMATIONAL' },
                        'Confidence': 99,
                        'Title': '[DynamoDB.1] DynamoDB tables should use KMS CMKs for encryption at rest',
                        'Description': 'DynamoDB table ' + tableName + ' is using a KMS CMK for encryption.',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'When you access an encrypted table, DynamoDB decrypts the table data transparently. You can switch between the AWS owned CMK, AWS managed CMK, and customer managed CMK at any given time. For more information refer to the DynamoDB Encryption at Rest section of the Amazon DynamoDB Developer Guide',
                                'Url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'AwsDynamoDbTable',
                                'Id': tableArn,
                                
                                'Partition': awsPartition,
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 'tableName': tableName }
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
                    yield finding
            except Exception as e:
                if str(e) == "'SSEDescription'":
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    finding={
                        'SchemaVersion': '2018-10-08',
                        'Id': tableArn + '/ddb-kms-cmk-check',
                        'ProductArn': f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        'GeneratorId': tableArn,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'MEDIUM' },
                        'Confidence': 99,
                        'Title': '[DynamoDB.1] DynamoDB tables should use KMS CMKs for encryption at rest',
                        'Description': 'DynamoDB table ' + tableName + ' is not using a KMS CMK for encryption. Refer to the remediation instructions if this configuration is not intended',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'When you access an encrypted table, DynamoDB decrypts the table data transparently. You can switch between the AWS owned CMK, AWS managed CMK, and customer managed CMK at any given time. For more information refer to the DynamoDB Encryption at Rest section of the Amazon DynamoDB Developer Guide',
                                'Url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'AwsDynamoDbTable',
                                'Id': tableArn,
                                
                                'Partition': awsPartition,
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 'tableName': tableName }
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
                    yield finding
                else:
                    print(e)

@registry.register_check("dynamodb")
def ddb_pitr_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DynamoDB.2] DynamoDB tables should have Point-in-Time Recovery (PITR) enabled"""
    iterator = paginate(cache=cache)
    for page in iterator:
        for table in page['TableNames']:
            tableName = str(table)
            tableArn = dynamodb.describe_table(TableName=tableName)['Table']['TableArn']
            try:
                response = dynamodb.describe_continuous_backups(TableName=tableName)
                pitrCheck = str(response['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'])
                if pitrCheck == 'DISABLED':
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    finding={
                        'SchemaVersion': '2018-10-08',
                        'Id': tableArn + '/ddb-pitr-check',
                        'ProductArn': f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        'GeneratorId': tableArn,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'LOW' },
                        'Confidence': 99,
                        'Title': '[DynamoDB.2] DynamoDB tables should have Point-in-Time Recovery (PITR) enabled',
                        'Description': 'DynamoDB table ' + tableName + ' does not have Point-in-Time Recovery (PITR) enabled. Amazon DynamoDB point-in-time recovery (PITR) provides automatic backups of your DynamoDB table data, LatestRestorableDateTime is typically 5 minutes before the current time. You should consider enabling this for applications with low RTO/RPOs. Refer to the remediation instructions if this configuration is not intended',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'For more information on enabling PITR refer to the Point-in-Time Recovery: How It Works section of the Amazon DynamoDB Developer Guide',
                                'Url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'AwsDynamoDbTable',
                                'Id': tableArn,
                                
                                'Partition': awsPartition,
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 'tableName': tableName }
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
                    yield finding
                else:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    finding={
                        'SchemaVersion': '2018-10-08',
                        'Id': tableArn + '/ddb-pitr-check',
                        'ProductArn': f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        'GeneratorId': tableArn,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'INFORMATIONAL' },
                        'Confidence': 99,
                        'Title': '[DynamoDB.2] DynamoDB tables should have Point-in-Time Recovery (PITR) enabled',
                        'Description': 'DynamoDB table ' + tableName + ' has Point-in-Time Recovery (PITR) enabled.',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'For more information on enabling PITR refer to the Point-in-Time Recovery: How It Works section of the Amazon DynamoDB Developer Guide',
                                'Url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'AwsDynamoDbTable',
                                'Id': tableArn,
                                
                                'Partition': awsPartition,
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 'tableName': tableName }
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
                    yield finding
            except Exception as e:
                print(e)

@registry.register_check("dynamodb")
def ddb_ttl_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DynamoDB.3] DynamoDB tables should have Time to Live (TTL) enabled"""
    iterator = paginate(cache=cache)
    for page in iterator:
        for table in page['TableNames']:
            tableName = str(table)
            tableArn = dynamodb.describe_table(TableName=tableName)['Table']['TableArn']
            try:
                response = dynamodb.describe_time_to_live(TableName=tableName)
                ttlCheck = str(response['TimeToLiveDescription']['TimeToLiveStatus'])
                if ttlCheck == 'DISABLED':
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    finding={
                        'SchemaVersion': '2018-10-08',
                        'Id': tableArn + '/ddb-ttl-check',
                        'ProductArn': f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        'GeneratorId': tableArn,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'LOW' },
                        'Confidence': 99,
                        'Title': '[DynamoDB.3] DynamoDB tables should have Time to Live (TTL) enabled',
                        'Description': 'DynamoDB table ' + tableName + ' does not have Time to Live (TTL) enabled. TTL allows you to automatically expire items from your table that are no longer needed to potentially reduce costs. Refer to the remediation instructions if this configuration is not intended',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'For more information on enabling TTL refer to the Using DynamoDB Time to Live (TTL) section of the Amazon DynamoDB Developer Guide',
                                'Url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/time-to-live-ttl-before-you-start.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'AwsDynamoDbTable',
                                'Id': tableArn,
                                
                                'Partition': awsPartition,
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 'tableName': tableName }
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
                    yield finding
                else:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    finding={
                        'SchemaVersion': '2018-10-08',
                        'Id': tableArn + '/ddb-ttl-check',
                        'ProductArn': f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        'GeneratorId': tableArn,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'INFORMATIONAL' },
                        'Confidence': 99,
                        'Title': '[DynamoDB.3] DynamoDB tables should have Time to Live (TTL) enabled',
                        'Description': 'DynamoDB table ' + tableName + ' has Time to Live (TTL) enabled.',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'For more information on enabling TTL refer to the Using DynamoDB Time to Live (TTL) section of the Amazon DynamoDB Developer Guide',
                                'Url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/time-to-live-ttl-before-you-start.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'AwsDynamoDbTable',
                                'Id': tableArn,
                                
                                'Partition': awsPartition,
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 'tableName': tableName }
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
                    yield finding
            except Exception as e:
                print(e)