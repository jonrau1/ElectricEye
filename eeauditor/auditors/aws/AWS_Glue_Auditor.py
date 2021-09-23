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
glue = boto3.client("glue")

def list_crawlers(cache):
    response = cache.get("list_crawlers")
    if response:
        return response
    cache["list_crawlers"] = glue.list_crawlers()
    return cache["list_crawlers"]

@registry.register_check("glue")
def crawler_s3_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Glue.1] AWS Glue crawler security configurations should enable Amazon S3 encryption"""
    crawler = list_crawlers(cache=cache)
    myCrawlers = crawler["CrawlerNames"]
    for crawlers in myCrawlers:
        crawlerName = str(crawlers)
        crawlerArn = f"arn:{awsPartition}:glue:{awsRegion}:{awsAccountId}:crawler/{crawlerName}"
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            response = glue.get_crawler(Name=crawlerName)
            crawlerSecConfig = str(response["Crawler"]["CrawlerSecurityConfiguration"])
            try:
                response = glue.get_security_configuration(Name=crawlerSecConfig)
                try:
                    s3EncryptionCheck = str(response["SecurityConfiguration"]["EncryptionConfiguration"]["S3Encryption"][0]["S3EncryptionMode"])
                except:
                    s3EncryptionCheck = "DISABLED"
                if s3EncryptionCheck == "DISABLED":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": crawlerArn + "/glue-crawler-s3-encryption-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": crawlerArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[Glue.1] AWS Glue crawler security configurations should enable Amazon S3 encryption",
                        "Description": "AWS Glue crawler "
                        + crawlerName
                        + " does not have a security configuration that enables S3 encryption. When you are writing Amazon S3 data, you use either server-side encryption with Amazon S3 managed keys (SSE-S3) or server-side encryption with AWS KMS managed keys (SSE-KMS). Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide",
                                "Url": "https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsGlueCrawler",
                                "Id": crawlerArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "crawlerName": crawlerName,
                                        "securityConfigurationId": crawlerSecConfig,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.DS-1",
                                "NIST SP 800-53 MP-8",
                                "NIST SP 800-53 SC-12",
                                "NIST SP 800-53 SC-28",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.8.2.3",
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": crawlerArn + "/glue-crawler-s3-encryption-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": crawlerArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Glue.1] AWS Glue crawler security configurations should enable Amazon S3 encryption",
                        "Description": "AWS Glue crawler "
                        + crawlerName
                        + " has a security configuration that enables S3 encryption.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide",
                                "Url": "https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsGlueCrawler",
                                "Id": crawlerArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "crawlerName": crawlerName,
                                        "securityConfigurationId": crawlerSecConfig,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.DS-1",
                                "NIST SP 800-53 MP-8",
                                "NIST SP 800-53 SC-12",
                                "NIST SP 800-53 SC-28",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.8.2.3",
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
            except Exception as e:
                if str(e) == "'CrawlerSecurityConfiguration'":
                    pass
                else:
                    print(e)
        except Exception as e:
            if str(e) == "'CrawlerSecurityConfiguration'":
                pass
            else:
                print(e)

@registry.register_check("glue")
def crawler_cloudwatch_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Glue.2] AWS Glue crawler security configurations should enable Amazon CloudWatch Logs encryption"""
    crawler = list_crawlers(cache=cache)
    myCrawlers = crawler["CrawlerNames"]
    for crawlers in myCrawlers:
        crawlerName = str(crawlers)
        crawlerArn = f"arn:{awsPartition}:glue:{awsRegion}:{awsAccountId}:crawler/{crawlerName}"
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            response = glue.get_crawler(Name=crawlerName)
            crawlerSecConfig = str(response["Crawler"]["CrawlerSecurityConfiguration"])
            try:
                response = glue.get_security_configuration(Name=crawlerSecConfig)
                try:
                    cwEncryptionCheck = str(response["SecurityConfiguration"]["EncryptionConfiguration"]["CloudWatchEncryption"]["CloudWatchEncryptionMode"])
                except:
                    cwEncryptionCheck = "DISABLED"
                if cwEncryptionCheck == "DISABLED":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": crawlerArn + "/glue-crawler-cloudwatch-encryption-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": crawlerArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[Glue.2] AWS Glue crawler security configurations should enable Amazon CloudWatch Logs encryption",
                        "Description": "AWS Glue crawler "
                        + crawlerName
                        + " does not have a security configuration that enables CloudWatch Logs encryption. Server-side (SSE-KMS) encryption is used to encrypt CloudWatch Logs. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide",
                                "Url": "https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsGlueCrawler",
                                "Id": crawlerArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "crawlerName": crawlerName,
                                        "securityConfigurationId": crawlerSecConfig,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.DS-1",
                                "NIST SP 800-53 MP-8",
                                "NIST SP 800-53 SC-12",
                                "NIST SP 800-53 SC-28",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.8.2.3",
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": crawlerArn + "/glue-crawler-cloudwatch-encryption-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": crawlerArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Glue.2] AWS Glue crawler security configurations should enable Amazon CloudWatch Logs encryption",
                        "Description": "AWS Glue crawler "
                        + crawlerName
                        + " has a security configuration that enables CloudWatch Logs encryption.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide",
                                "Url": "https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsGlueCrawler",
                                "Id": crawlerArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "crawlerName": crawlerName,
                                        "securityConfigurationId": crawlerSecConfig,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.DS-1",
                                "NIST SP 800-53 MP-8",
                                "NIST SP 800-53 SC-12",
                                "NIST SP 800-53 SC-28",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.8.2.3",
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
            except Exception as e:
                if str(e) == "'CrawlerSecurityConfiguration'":
                    pass
                else:
                    print(e)
        except Exception as e:
            if str(e) == "'CrawlerSecurityConfiguration'":
                pass
            else:
                print(e)

@registry.register_check("glue")
def crawler_job_bookmark_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Glue.3] AWS Glue crawler security configurations should enable job bookmark encryption"""
    crawler = list_crawlers(cache=cache)
    myCrawlers = crawler["CrawlerNames"]
    for crawlers in myCrawlers:
        crawlerName = str(crawlers)
        crawlerArn = f"arn:{awsPartition}:glue:{awsRegion}:{awsAccountId}:crawler/{crawlerName}"
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            response = glue.get_crawler(Name=crawlerName)
            crawlerSecConfig = str(response["Crawler"]["CrawlerSecurityConfiguration"])
            try:
                response = glue.get_security_configuration(Name=crawlerSecConfig)
                try:
                    jobBookmarkEncryptionCheck = str(response["SecurityConfiguration"]["EncryptionConfiguration"]["JobBookmarksEncryption"]["JobBookmarksEncryptionMode"])
                except:
                    jobBookmarkEncryptionCheck = "DISABLED"
                if jobBookmarkEncryptionCheck == "DISABLED":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": crawlerArn + "/glue-crawler-job-bookmark-encryption-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": crawlerArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[Glue.3] AWS Glue crawler security configurations should enable job bookmark encryption",
                        "Description": "AWS Glue crawler "
                        + crawlerName
                        + " does not have a security configuration that enables job bookmark encryption. Client-side (CSE-KMS) encryption is used to encrypt job bookmarks, bookmark data is encrypted before it is sent to Amazon S3 for storage. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide",
                                "Url": "https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsGlueCrawler",
                                "Id": crawlerArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "crawlerName": crawlerName,
                                        "securityConfigurationId": crawlerSecConfig,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.DS-1",
                                "NIST SP 800-53 MP-8",
                                "NIST SP 800-53 SC-12",
                                "NIST SP 800-53 SC-28",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.8.2.3",
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": crawlerArn + "/glue-crawler-job-bookmark-encryption-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": crawlerArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Glue.3] AWS Glue crawler security configurations should enable job bookmark encryption",
                        "Description": "AWS Glue crawler "
                        + crawlerName
                        + " has a security configuration that enables job bookmark encryption.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on encryption and AWS Glue security configurations refer to the Working with Security Configurations on the AWS Glue Console section of the AWS Glue Developer Guide",
                                "Url": "https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsGlueCrawler",
                                "Id": crawlerArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "crawlerName": crawlerName,
                                        "securityConfigurationId": crawlerSecConfig,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.DS-1",
                                "NIST SP 800-53 MP-8",
                                "NIST SP 800-53 SC-12",
                                "NIST SP 800-53 SC-28",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.8.2.3",
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
            except Exception as e:
                if str(e) == "'CrawlerSecurityConfiguration'":
                    pass
                else:
                    print(e)
        except Exception as e:
            if str(e) == "'CrawlerSecurityConfiguration'":
                pass
            else:
                print(e)

@registry.register_check("glue")
def glue_data_catalog_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Glue.4] AWS Glue data catalogs should be encrypted at rest"""
    catalogArn = f"arn:{awsPartition}:glue:{awsRegion}:{awsAccountId}:catalog"
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    try:
        response = glue.get_data_catalog_encryption_settings()
        try:
            catalogEncryptionCheck = str(response["DataCatalogEncryptionSettings"]["EncryptionAtRest"]["CatalogEncryptionMode"])
        except:
            catalogEncryptionCheck = "DISABLED"
        if catalogEncryptionCheck == "DISABLED":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": catalogArn + "/glue-data-catalog-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": catalogArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Glue.4] AWS Glue data catalogs should be encrypted at rest",
                "Description": "The AWS Glue data catalog for account "
                + awsAccountId
                + " is not encrypted. You can enable or disable encryption settings for the entire Data Catalog. In the process, you specify an AWS KMS key that is automatically used when objects, such as tables, databases, partitions, table versions, connections and/or user-defined functions, are written to the Data Catalog. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on data catalog encryption refer to the Encrypting Your Data Catalog section of the AWS Glue Developer Guide",
                        "Url": "https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsGlueDataCatalog",
                        "Id": catalogArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-1",
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": catalogArn + "/glue-data-catalog-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": catalogArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Glue.4] AWS Glue data catalogs should be encrypted at rest",
                "Description": "The AWS Glue data catalog for account "
                + awsAccountId
                + " is encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on data catalog encryption refer to the Encrypting Your Data Catalog section of the AWS Glue Developer Guide",
                        "Url": "https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsGlueDataCatalog",
                        "Id": catalogArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-1",
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
    except Exception as e:
        if str(e) == "'CrawlerSecurityConfiguration'":
            pass
        else:
            print(e)

@registry.register_check("glue")
def glue_data_catalog_password_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Glue.5] AWS Glue data catalogs should be configured to encrypt connection passwords"""
    catalogArn = f"arn:{awsPartition}:glue:{awsRegion}:{awsAccountId}:catalog"
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    try:
        response = glue.get_data_catalog_encryption_settings()
        try:
            passwordEncryptionCheck = str(response["DataCatalogEncryptionSettings"]["ConnectionPasswordEncryption"]["ReturnConnectionPasswordEncrypted"])
        except:
            passwordEncryptionCheck = "False"
        if passwordEncryptionCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": catalogArn + "/glue-data-catalog-password-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": catalogArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Glue.5] AWS Glue data catalogs should be configured to encrypt connection passwords",
                "Description": "The AWS Glue data catalog for account "
                + awsAccountId
                + " is not configured to encrypt connection passwords. You can retrieve connection passwords in the AWS Glue Data Catalog by using the GetConnection and GetConnections API operations. These passwords are stored in the Data Catalog connection and are used when AWS Glue connects to a Java Database Connectivity (JDBC) data store. When the connection was created or updated, an option in the Data Catalog settings determined whether the password was encrypted. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on data catalog connection password encryption refer to the Encrypting Connection Passwords section of the AWS Glue Developer Guide",
                        "Url": "https://docs.aws.amazon.com/glue/latest/dg/encrypt-connection-passwords.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsGlueDataCatalog",
                        "Id": catalogArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-1",
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": catalogArn + "/glue-data-catalog-password-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": catalogArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Glue.5] AWS Glue data catalogs should be configured to encrypt connection passwords",
                "Description": "The AWS Glue data catalog for account "
                + awsAccountId
                + " is configured to encrypt connection passwords.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on data catalog connection password encryption refer to the Encrypting Connection Passwords section of the AWS Glue Developer Guide",
                        "Url": "https://docs.aws.amazon.com/glue/latest/dg/encrypt-connection-passwords.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsGlueDataCatalog",
                        "Id": catalogArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-1",
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
    except Exception as e:
        if str(e) == "'CrawlerSecurityConfiguration'":
            pass
        else:
            print(e)

@registry.register_check("glue")
def glue_data_catalog_resource_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Glue.6] AWS Glue data catalogs should enforce fine-grained access controls with a resource policy"""
    catalogArn = f"arn:{awsPartition}:glue:{awsRegion}:{awsAccountId}:catalog"
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    try:
        response = glue.get_resource_policy()
        policyHash = str(response["PolicyHash"])
        # this is a passing check
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": catalogArn + "/glue-data-catalog-resource-policy-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": catalogArn,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Glue.6] AWS Glue data catalogs should enforce fine-grained access controls with a resource policy",
            "Description": "The AWS Glue data catalog for account "
            + awsAccountId
            + " uses a resource policy.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on data catalog resource policies refer to the AWS Glue Resource Policies for Access Control section of the AWS Glue Developer Guide",
                    "Url": "https://docs.aws.amazon.com/glue/latest/dg/glue-resource-policies.html",
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsGlueDataCatalog",
                    "Id": catalogArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {"Other": {"policyHash": policyHash}},
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.AC-1",
                    "NIST SP 800-53 AC-1",
                    "NIST SP 800-53 AC-2",
                    "NIST SP 800-53 IA-1",
                    "NIST SP 800-53 IA-2",
                    "NIST SP 800-53 IA-3",
                    "NIST SP 800-53 IA-4",
                    "NIST SP 800-53 IA-5",
                    "NIST SP 800-53 IA-6",
                    "NIST SP 800-53 IA-7",
                    "NIST SP 800-53 IA-8",
                    "NIST SP 800-53 IA-9",
                    "NIST SP 800-53 IA-10",
                    "NIST SP 800-53 IA-11",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.2",
                    "ISO 27001:2013 A.9.2.1",
                    "ISO 27001:2013 A.9.2.2",
                    "ISO 27001:2013 A.9.2.3",
                    "ISO 27001:2013 A.9.2.4",
                    "ISO 27001:2013 A.9.2.6",
                    "ISO 27001:2013 A.9.3.1",
                    "ISO 27001:2013 A.9.4.2",
                    "ISO 27001:2013 A.9.4.3",
                ],
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED",
        }
        yield finding
    except Exception as e:
        if (
            str(e)
            == "An error occurred (EntityNotFoundException) when calling the GetResourcePolicy operation: Policy not found"
        ):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": catalogArn + "/glue-data-catalog-resource-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": catalogArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Glue.6] AWS Glue data catalogs should enforce fine-grained access controls with a resource policy",
                "Description": "The AWS Glue data catalog for account "
                + awsAccountId
                + " does not use a resource policy. AWS Glue supports using resource policies to control access to Data Catalog resources. These resources include databases, tables, connections, and user-defined functions, along with the Data Catalog APIs that interact with these resources. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on data catalog resource policies refer to the AWS Glue Resource Policies for Access Control section of the AWS Glue Developer Guide",
                        "Url": "https://docs.aws.amazon.com/glue/latest/dg/glue-resource-policies.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsGlueDataCatalog",
                        "Id": catalogArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            print(e)