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
import datetime
import os
# import boto3 clients
sts = boto3.client('sts')
glue = boto3.client('glue')
securityhub = boto3.client('securityhub')
# create account id & region variables
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through Glue Crawlers
try:
    response = glue.list_crawlers()
    myCrawlers = response['CrawlerNames']
except Exception as e:
    print(e)

def crawler_s3_encryption_check():
    for crawlers in myCrawlers:
        crawlerName = str(crawlers)
        crawlerArn = 'arn:aws:glue:' + awsRegion + ':' + awsAccountId + ':crawler/' + crawlerName
        try:
            response = glue.get_crawler(Name=crawlerName)
            crawlerSecConfig = str(response['Crawler']['CrawlerSecurityConfiguration'])
            try:
                response = glue.get_security_configuration(Name=crawlerSecConfig)
                s3EncryptionCheck = str(response['SecurityConfiguration']['EncryptionConfiguration']['S3Encryption'][0]['S3EncryptionMode'])
                if s3EncryptionCheck == 'DISABLED':
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': crawlerArn + '/glue-crawler-s3-encryption-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': crawlerArn,
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
                                    'Title': '[Glue.1] AWS Glue crawler security configurations should enable Amazon S3 encryption',
                                    'Description': 'AWS Glue crawler ' + crawlerName + ' does not have a security configuration that enables S3 encryption. When you are writing Amazon S3 data, you use either server-side encryption with Amazon S3 managed keys (SSE-S3) or server-side encryption with AWS KMS managed keys (SSE-KMS). Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide',
                                            'Url': 'https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsGlueCrawler',
                                            'Id': crawlerArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 
                                                    'crawlerName': crawlerName,
                                                    'securityConfigurationId': crawlerSecConfig
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
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': crawlerArn + '/glue-crawler-s3-encryption-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': crawlerArn,
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
                                    'Title': '[Glue.1] AWS Glue crawler security configurations should enable Amazon S3 encryption',
                                    'Description': 'AWS Glue crawler ' + crawlerName + ' has a security configuration that enables S3 encryption.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide',
                                            'Url': 'https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsGlueCrawler',
                                            'Id': crawlerArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 
                                                    'crawlerName': crawlerName,
                                                    'securityConfigurationId': crawlerSecConfig
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
            except Exception as e:
                print(e)
        except Exception as e:
            print(e)

def crawler_cloudwatch_encryption_check():
    for crawlers in myCrawlers:
        crawlerName = str(crawlers)
        crawlerArn = 'arn:aws:glue:' + awsRegion + ':' + awsAccountId + ':crawler/' + crawlerName
        try:
            response = glue.get_crawler(Name=crawlerName)
            crawlerSecConfig = str(response['Crawler']['CrawlerSecurityConfiguration'])
            try:
                response = glue.get_security_configuration(Name=crawlerSecConfig)
                cwEncryptionCheck = str(response['SecurityConfiguration']['EncryptionConfiguration']['CloudWatchEncryption']['CloudWatchEncryptionMode'])
                if cwEncryptionCheck == 'DISABLED':
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': crawlerArn + '/glue-crawler-cloudwatch-encryption-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': crawlerArn,
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
                                    'Title': '[Glue.2] AWS Glue crawler security configurations should enable Amazon CloudWatch Logs encryption',
                                    'Description': 'AWS Glue crawler ' + crawlerName + ' does not have a security configuration that enables CloudWatch Logs encryption. Server-side (SSE-KMS) encryption is used to encrypt CloudWatch Logs. Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide',
                                            'Url': 'https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsGlueCrawler',
                                            'Id': crawlerArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 
                                                    'crawlerName': crawlerName,
                                                    'securityConfigurationId': crawlerSecConfig
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
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': crawlerArn + '/glue-crawler-cloudwatch-encryption-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': crawlerArn,
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
                                    'Title': '[Glue.2] AWS Glue crawler security configurations should enable Amazon CloudWatch Logs encryption',
                                    'Description': 'AWS Glue crawler ' + crawlerName + ' has a security configuration that enables CloudWatch Logs encryption.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide',
                                            'Url': 'https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsGlueCrawler',
                                            'Id': crawlerArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 
                                                    'crawlerName': crawlerName,
                                                    'securityConfigurationId': crawlerSecConfig
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
            except Exception as e:
                print(e)
        except Exception as e:
            print(e)

def crawler_job_bookmark_encryption_check():
    for crawlers in myCrawlers:
        crawlerName = str(crawlers)
        crawlerArn = 'arn:aws:glue:' + awsRegion + ':' + awsAccountId + ':crawler/' + crawlerName
        try:
            response = glue.get_crawler(Name=crawlerName)
            crawlerSecConfig = str(response['Crawler']['CrawlerSecurityConfiguration'])
            try:
                response = glue.get_security_configuration(Name=crawlerSecConfig)
                jobBookmarkEncryptionCheck = str(response['SecurityConfiguration']['EncryptionConfiguration']['JobBookmarksEncryption']['JobBookmarksEncryptionMode'])
                if jobBookmarkEncryptionCheck == 'DISABLED':
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': crawlerArn + '/glue-crawler-job-bookmark-encryption-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': crawlerArn,
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
                                    'Title': '[Glue.3] AWS Glue crawler security configurations should enable job bookmark encryption',
                                    'Description': 'AWS Glue crawler ' + crawlerName + ' does not have a security configuration that enables job bookmark encryption. Client-side (CSE-KMS) encryption is used to encrypt job bookmarks, bookmark data is encrypted before it is sent to Amazon S3 for storage. Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide',
                                            'Url': 'https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsGlueCrawler',
                                            'Id': crawlerArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 
                                                    'crawlerName': crawlerName,
                                                    'securityConfigurationId': crawlerSecConfig
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
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': crawlerArn + '/glue-crawler-job-bookmark-encryption-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': crawlerArn,
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
                                    'Title': '[Glue.3] AWS Glue crawler security configurations should enable job bookmark encryption',
                                    'Description': 'AWS Glue crawler ' + crawlerName + ' has a security configuration that enables job bookmark encryption.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide',
                                            'Url': 'https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsGlueCrawler',
                                            'Id': crawlerArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 
                                                    'crawlerName': crawlerName,
                                                    'securityConfigurationId': crawlerSecConfig
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
            except Exception as e:
                print(e)
        except Exception as e:
            print(e)

def glue_data_catalog_encryption_check():
    catalogArn = 'arn:aws:glue:' + awsRegion + ':' + awsAccountId + ':catalog'
    try:
        response = glue.get_data_catalog_encryption_settings()
        catalogEncryptionCheck = str(response['DataCatalogEncryptionSettings']['EncryptionAtRest']['CatalogEncryptionMode'])
        if catalogEncryptionCheck == 'DISABLED':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': catalogArn + '/glue-data-catalog-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': catalogArn,
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
                            'Title': '[Glue.4] AWS Glue data catalogs should be encrypted at rest',
                            'Description': 'The AWS Glue data catalog for account ' + awsAccountId + ' is not encrypted. You can enable or disable encryption settings for the entire Data Catalog. In the process, you specify an AWS KMS key that is automatically used when objects, such as tables, databases, partitions, table versions, connections and/or user-defined functions, are written to the Data Catalog. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on data catalog encryption refer to the Encrypting Your Data Catalog section of the AWS Glue Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsGlueDataCatalog',
                                    'Id': catalogArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion
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
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': catalogArn + '/glue-data-catalog-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': catalogArn,
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
                            'Title': '[Glue.4] AWS Glue data catalogs should be encrypted at rest',
                            'Description': 'The AWS Glue data catalog for account ' + awsAccountId + ' is encrypted.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on data catalog encryption refer to the Encrypting Your Data Catalog section of the AWS Glue Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsGlueDataCatalog',
                                    'Id': catalogArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion
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

def glue_data_catalog_password_encryption_check():
    catalogArn = 'arn:aws:glue:' + awsRegion + ':' + awsAccountId + ':catalog'
    try:
        response = glue.get_data_catalog_encryption_settings()
        passwordEncryptionCheck = str(response['DataCatalogEncryptionSettings']['ConnectionPasswordEncryption']['ReturnConnectionPasswordEncrypted'])
        if passwordEncryptionCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': catalogArn + '/glue-data-catalog-password-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': catalogArn,
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
                            'Title': '[Glue.5] AWS Glue data catalogs should be configured to encrypt connection passwords',
                            'Description': 'The AWS Glue data catalog for account ' + awsAccountId + ' is not configured to encrypt connection passwords. You can retrieve connection passwords in the AWS Glue Data Catalog by using the GetConnection and GetConnections API operations. These passwords are stored in the Data Catalog connection and are used when AWS Glue connects to a Java Database Connectivity (JDBC) data store. When the connection was created or updated, an option in the Data Catalog settings determined whether the password was encrypted. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on data catalog connection password encryption refer to the Encrypting Connection Passwords section of the AWS Glue Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/glue/latest/dg/encrypt-connection-passwords.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsGlueDataCatalog',
                                    'Id': catalogArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion
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
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': catalogArn + '/glue-data-catalog-password-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': catalogArn,
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
                            'Title': '[Glue.5] AWS Glue data catalogs should be configured to encrypt connection passwords',
                            'Description': 'The AWS Glue data catalog for account ' + awsAccountId + ' is configured to encrypt connection passwords.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on data catalog connection password encryption refer to the Encrypting Connection Passwords section of the AWS Glue Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/glue/latest/dg/encrypt-connection-passwords.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsGlueDataCatalog',
                                    'Id': catalogArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion
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

def glue_data_catalog_resource_policy_check():
    catalogArn = 'arn:aws:glue:' + awsRegion + ':' + awsAccountId + ':catalog'
    try:
        response = glue.get_resource_policy()
        policyHash = str(response['PolicyHash'])
        # this is a passing check
        try:
            # ISO Time
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': catalogArn + '/glue-data-catalog-resource-policy-check',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                        'GeneratorId': catalogArn,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'INFORMATIONAL' },
                        'Confidence': 99,
                        'Title': '[Glue.6] AWS Glue data catalogs should enforce fine-grained access controls with a resource policy',
                        'Description': 'The AWS Glue data catalog for account ' + awsAccountId + ' uses a resource policy.',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'For more information on data catalog resource policies refer to the AWS Glue Resource Policies for Access Control section of the AWS Glue Developer Guide',
                                'Url': 'https://docs.aws.amazon.com/glue/latest/dg/glue-resource-policies.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'AwsGlueDataCatalog',
                                'Id': catalogArn,
                                'Partition': 'aws',
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 
                                        'policyHash': policyHash
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
    except Exception as e:
        if str(e) == 'An error occurred (EntityNotFoundException) when calling the GetResourcePolicy operation: Policy not found':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': catalogArn + '/glue-data-catalog-resource-policy-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': catalogArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'MEDIUM' },
                            'Confidence': 99,
                            'Title': '[Glue.6] AWS Glue data catalogs should enforce fine-grained access controls with a resource policy',
                            'Description': 'The AWS Glue data catalog for account ' + awsAccountId + ' does not use a resource policy. AWS Glue supports using resource policies to control access to Data Catalog resources. These resources include databases, tables, connections, and user-defined functions, along with the Data Catalog APIs that interact with these resources. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on data catalog resource policies refer to the AWS Glue Resource Policies for Access Control section of the AWS Glue Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/glue/latest/dg/glue-resource-policies.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsGlueDataCatalog',
                                    'Id': catalogArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion
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
            print(e)

def glue_auditor():
    crawler_s3_encryption_check()
    crawler_cloudwatch_encryption_check()
    crawler_job_bookmark_encryption_check()
    glue_data_catalog_encryption_check()
    glue_data_catalog_password_encryption_check()
    glue_data_catalog_resource_policy_check()

glue_auditor()