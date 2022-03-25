#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
elasticsearch = boto3.client("es")
# loop through elasticsearch domains
def list_domain_names(cache):
    response = cache.get("list_domain_names")
    if response:
        return response
    cache["list_domain_names"] = elasticsearch.list_domain_names()
    return cache["list_domain_names"]


@registry.register_check("es")
def dedicated_master_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.1] OpenSearch/AWS ElasticSearch Service domains should use dedicated master nodes"""
    response = list_domain_names(cache)
    myDomainNames = response["DomainNames"]
    for domains in myDomainNames:
        esDomainName = str(domains["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        domainId = str(response["DomainStatus"]["DomainId"])
        domainArn = str(response["DomainStatus"]["ARN"])
        dedicatedMasterCheck = str(
            response["DomainStatus"]["ElasticsearchClusterConfig"]["DedicatedMasterEnabled"]
        )
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if dedicatedMasterCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-dedicated-master-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OpenSearch.1] OpenSearch/AWS ElasticSearch Service domains should use dedicated master nodes",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " does not use dedicated master nodes. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should dedicated master nodes enabled refer to the Configuring Amazon ES Domains section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomains-configure-cluster",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF ID.BE-5",
                        "NIST CSF PR.PT-5",
                        "NIST SP 800-53 CP-2",
                        "NIST SP 800-53 CP-11",
                        "NIST SP 800-53 SA-13",
                        "NIST SP 800-53 SA14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-dedicated-master-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OpenSearch.1] OpenSearch/AWS ElasticSearch Service domains should use dedicated master nodes",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " uses dedicated master nodes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should dedicated master nodes enabled refer to the Configuring Amazon ES Domains section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomains-configure-cluster",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF ID.BE-5",
                        "NIST CSF PR.PT-5",
                        "NIST SP 800-53 CP-2",
                        "NIST SP 800-53 CP-11",
                        "NIST SP 800-53 SA-13",
                        "NIST SP 800-53 SA14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("es")
def cognito_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.2] OpenSearch/AWS ElasticSearch Service domains should use Cognito authentication for Kibana"""
    response = list_domain_names(cache)
    myDomainNames = response["DomainNames"]
    for domains in myDomainNames:
        esDomainName = str(domains["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        domainId = str(response["DomainStatus"]["DomainId"])
        domainArn = str(response["DomainStatus"]["ARN"])
        try:
            cognitoEnabledCheck = str(response["DomainStatus"]["CognitoOptions"]["Enabled"])
        except:
            cognitoEnabledCheck = "False"
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if cognitoEnabledCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-cognito-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OpenSearch.2] OpenSearch/AWS ElasticSearch Service domains should use Cognito authentication for Kibana",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " does not use Cognito authentication for Kibana. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should use Cognito authentication for Kibana refer to the Amazon Cognito Authentication for Kibana section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-6",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AC-3",
                        "NIST SP 800-53 AC-16",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-24",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 PE-2",
                        "NIST SP 800-53 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-cognito-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OpenSearch.2] OpenSearch/AWS ElasticSearch Service domains should use Cognito authentication for Kibana",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " uses Cognito authentication for Kibana.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should use Cognito authentication for Kibana refer to the Amazon Cognito Authentication for Kibana section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-6",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AC-3",
                        "NIST SP 800-53 AC-16",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-24",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 PE-2",
                        "NIST SP 800-53 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("es")
def encryption_at_rest_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.3] OpenSearch/AWS ElasticSearch Service domains should be encrypted at rest"""
    response = list_domain_names(cache)
    myDomainNames = response["DomainNames"]
    for domains in myDomainNames:
        esDomainName = str(domains["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        domainId = str(response["DomainStatus"]["DomainId"])
        domainArn = str(response["DomainStatus"]["ARN"])
        encryptionAtRestCheck = str(response["DomainStatus"]["EncryptionAtRestOptions"]["Enabled"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if encryptionAtRestCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-encryption-at-rest-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
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
                "Title": "[OpenSearch.3] OpenSearch/AWS ElasticSearch Service domains should be encrypted at rest",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " is not encrypted at rest. You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 5.1 or later",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 5.1 or later.",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html#enabling-ear",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                                "EncryptionAtRestOptions": {"Enabled": False},
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
                "Id": domainArn + "/elasticsearch-encryption-at-rest-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
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
                "Title": "[OpenSearch.3] OpenSearch/AWS ElasticSearch Service domains should be encrypted at rest",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " is encrypted at rest",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 5.1 or later.",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html#enabling-ear",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                                "EncryptionAtRestOptions": {"Enabled": True},
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

@registry.register_check("es")
def node2node_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.4] OpenSearch/AWS ElasticSearch Service domains should use node-to-node encryption"""
    response = list_domain_names(cache)
    myDomainNames = response["DomainNames"]
    for domains in myDomainNames:
        esDomainName = str(domains["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        domainId = str(response["DomainStatus"]["DomainId"])
        domainArn = str(response["DomainStatus"]["ARN"])
        node2nodeEncryptionCheck = str(
            response["DomainStatus"]["NodeToNodeEncryptionOptions"]["Enabled"]
        )
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if node2nodeEncryptionCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-node2node-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
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
                "Title": "[OpenSearch.4] OpenSearch/AWS ElasticSearch Service domains should use node-to-node encryption",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " does not use node-to-node encryption. You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 6.0 or later",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 6.0 or later.",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                                "NodeToNodeEncryptionOptions": {"Enabled": False},
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-node2node-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
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
                "Title": "[OpenSearch.4] OpenSearch/AWS ElasticSearch Service domains should use node-to-node encryption",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " uses node-to-node encryption.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 6.0 or later.",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                                "NodeToNodeEncryptionOptions": {"Enabled": True},
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("es")
def https_enforcement_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.5] OpenSearch/AWS ElasticSearch Service domains should enforce HTTPS-only communications"""
    response = list_domain_names(cache)
    myDomainNames = response["DomainNames"]
    for domains in myDomainNames:
        esDomainName = str(domains["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        domainId = str(response["DomainStatus"]["DomainId"])
        domainArn = str(response["DomainStatus"]["ARN"])
        httpsEnforcementCheck = str(
            response["DomainStatus"]["DomainEndpointOptions"]["EnforceHTTPS"]
        )
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if httpsEnforcementCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-enforce-https-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
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
                "Title": "[OpenSearch.5] OpenSearch/AWS ElasticSearch Service domains should enforce HTTPS-only communications",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " does not enforce HTTPS-only communications. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should enforce HTTPS-only communications refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                                "DomainEndpointOptions": {"EnforceHTTPS": False},
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-enforce-https-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
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
                "Title": "[OpenSearch.5] OpenSearch/AWS ElasticSearch Service domains should enforce HTTPS-only communications",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " enforces HTTPS-only communications. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should enforce HTTPS-only communications refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                                "DomainEndpointOptions": {"EnforceHTTPS": True},
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("es")
def tls_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.6] OpenSearch/AWS ElasticSearch Service domains that enforce HTTPS-only communications should use a TLS 1.2 security policy"""
    response = list_domain_names(cache)
    myDomainNames = response["DomainNames"]
    for domains in myDomainNames:
        esDomainName = str(domains["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        domainId = str(response["DomainStatus"]["DomainId"])
        domainArn = str(response["DomainStatus"]["ARN"])
        httpsEnforcementCheck = str(
            response["DomainStatus"]["DomainEndpointOptions"]["EnforceHTTPS"]
        )
        if httpsEnforcementCheck == "True":
            # ISO Time
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            tlsPolicyCheck = str(
                response["DomainStatus"]["DomainEndpointOptions"]["TLSSecurityPolicy"]
            )
            if tlsPolicyCheck != "Policy-Min-TLS-1-2-2019-07":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": domainArn + "/elasticsearch-tls-1-2-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": domainArn,
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
                    "Title": "[OpenSearch.6] OpenSearch/AWS ElasticSearch Service domains that enforce HTTPS-only communications should use a TLS 1.2 security policy",
                    "Description": "OpenSearch/AWS ElasticSearch Service domain "
                    + esDomainName
                    + " does not use a TLS 1.2 security policy. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your domain should use a TLS 1.2 security policy refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsOpenSearchServiceDomain",
                            "Id": domainArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsOpenSearchServiceDomain": {
                                    "Id": domainId,
                                    "DomainName": esDomainName,
                                    "EngineVersion": esVersion,
                                    "DomainEndpointOptions": {
                                        "EnforceHTTPS": True,
                                        "TLSSecurityPolicy": tlsPolicyCheck,
                                    },
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-2",
                            "NIST SP 800-53 SC-8",
                            "NIST SP 800-53 SC-11",
                            "NIST SP 800-53 SC-12",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.2.1",
                            "ISO 27001:2013 A.13.2.3",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": domainArn + "/elasticsearch-tls-1-2-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": domainArn,
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
                    "Title": "[OpenSearch.6] OpenSearch/AWS ElasticSearch Service domains that enforce HTTPS-only communications should use a TLS 1.2 security policy",
                    "Description": "OpenSearch/AWS ElasticSearch Service domain "
                    + esDomainName
                    + " uses a TLS 1.2 security policy.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your domain should use a TLS 1.2 security policy refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsOpenSearchServiceDomain",
                            "Id": domainArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsOpenSearchServiceDomain": {
                                    "Id": domainId,
                                    "DomainName": esDomainName,
                                    "EngineVersion": esVersion,
                                    "DomainEndpointOptions": {
                                        "EnforceHTTPS": True,
                                        "TLSSecurityPolicy": tlsPolicyCheck,
                                    },
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-2",
                            "NIST SP 800-53 SC-8",
                            "NIST SP 800-53 SC-11",
                            "NIST SP 800-53 SC-12",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.2.1",
                            "ISO 27001:2013 A.13.2.3",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        else:
            pass

@registry.register_check("es")
def elastic_update_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.7] OpenSearch/AWS ElasticSearch Service domains should be updated to the latest service software version"""
    response = list_domain_names(cache)
    myDomainNames = response["DomainNames"]
    for domains in myDomainNames:
        esDomainName = str(domains["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        domainId = str(response["DomainStatus"]["DomainId"])
        domainArn = str(response["DomainStatus"]["ARN"])
        updateCheck = str(response["DomainStatus"]["ServiceSoftwareOptions"]["UpdateAvailable"])
        updateInformation = str(response["DomainStatus"]["ServiceSoftwareOptions"]["Description"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if updateCheck == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-version-update-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OpenSearch.7] OpenSearch/AWS ElasticSearch Service domains should be updated to the latest service software version",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " is not up to date. Service provided message follows: "
                + updateInformation
                + ". Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For update information refer to the Service Software Updates section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-service-software",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.MA-1",
                        "NIST SP 800-53 MA-2",
                        "NIST SP 800-53 MA-3",
                        "NIST SP 800-53 MA-5",
                        "NIST SP 800-53 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-version-update-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OpenSearch.7] OpenSearch/AWS ElasticSearch Service domains should be updated to the latest service software version",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " is up to date. Service provided message follows: "
                + updateInformation,
                "Remediation": {
                    "Recommendation": {
                        "Text": "For update information refer to the Service Software Updates section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-service-software",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion,
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.MA-1",
                        "NIST SP 800-53 MA-2",
                        "NIST SP 800-53 MA-3",
                        "NIST SP 800-53 MA-5",
                        "NIST SP 800-53 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("es")
def elasticsearch_in_vpc_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.8] OpenSearch/AWS ElasticSearch Service domains should be in a VPC"""
    response = list_domain_names(cache)
    myDomainNames = response["DomainNames"]
    for domains in myDomainNames:
        esDomainName = str(domains["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        domainId = str(response["DomainStatus"]["DomainId"])
        domainArn = str(response["DomainStatus"]["ARN"])
        try:
            vpcId = str(info["VPCOptions"]["VPCId"])
        except:
            vpcId = "NO_VPC"
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        # This is a failing check
        if vpcId == "NO_VPC":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-in-vpc-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OpenSearch.8] OpenSearch/AWS ElasticSearch Service domains should be in a VPC",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " is not in a VPC, Placing an Amazon ES domain within a VPC enables secure communication between Amazon ES and other services within the VPC without the need for an internet gateway, NAT device, or VPN connection. All traffic remains securely within the AWS Cloud. Because of their logical isolation, domains that reside within a VPC have an extra layer of security when compared to domains that use public endpoints. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on placing Domains in a VPC refer to the Launching your Amazon OpenSearch/AWS ElasticSearch Service domains using a VPC section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-3",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-17",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-20",
                        "NIST SP 800-53 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-in-vpc-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OpenSearch.8] OpenSearch/AWS ElasticSearch Service domains should be in a VPC",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " is in a VPC.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on placing Domains in a VPC refer to the Launching your Amazon OpenSearch/AWS ElasticSearch Service domains using a VPC section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-3",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-17",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-20",
                        "NIST SP 800-53 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("es")
def elasticsearch_public_access_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.9] OpenSearch/AWS ElasticSearch Service domains should not be exposed to the public"""
    response = list_domain_names(cache)
    myDomainNames = response["DomainNames"]
    for domains in myDomainNames:
        esDomainName = str(domains["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        domainId = str(response["DomainStatus"]["DomainId"])
        domainArn = str(response["DomainStatus"]["ARN"])
        # Determine if ES has Cognito Enabled
        try:
            cognitoEnabledCheck = str(response["DomainStatus"]["CognitoOptions"]["Enabled"])
        except:
            cognitoEnabledCheck = "False"
        # Determine if ES is in a VPC
        try:
            vpcId = str(info["VPCOptions"]["VPCId"])
        except:
            vpcId = "NO_VPC"
        # Determine if there is a policy and then parse through it. If the "AWS": "*" principal is allowed (anonymous access) without
        # any conditions we can assume there is not anything else to stop them
        try:
            policyDoc = info["AccessPolicies"]
            policyJson = json.loads(policyDoc.encode().decode("unicode_escape"))
            hasPolicy = "True"
            for sid in policyJson["Statement"]:
                try:
                    conditionCheck = str(sid["Condition"])
                    hasCondition = "True"
                except:
                    conditionCheck = ""
                    hasCondition = "False"
                if str(sid["Principal"]) == '{"AWS": "*"}' and hasCondition == "False":
                    policyAllowAnon = "True"
                else:
                    policyAllowAnon = "False"
        except:
            policyDoc = ""
            policyJson = "NO_POLICY"
            policyAllowAnon = "NO_POLICY"
            hasPolicy = "False"
        # Full Public Check
        if policyAllowAnon == "True" and vpcId == "NO_VPC" and cognitoEnabledCheck == "False":
            fullPublic = "True"
        else:
            fullPublic = "False"
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        # This is a failing check
        if fullPublic == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[OpenSearch.9] OpenSearch/AWS ElasticSearch Service domains should not be exposed to the public",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " is open to public due to not using a VPC, Cognito, or any additional conditions within the resource policy. Public access will allow malicious actors to attack the confidentiality, integrity or availability of documents indexed in your Domain. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on protecting Domains with a Resource-based Policy refer to the Identity and Access Management in Amazon Elasticsearch Service section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-ac.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-3",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-17",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-20",
                        "NIST SP 800-53 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/elasticsearch-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[OpenSearch.9] OpenSearch/AWS ElasticSearch Service domains should not be exposed to the public",
                "Description": "OpenSearch/AWS ElasticSearch Service domain "
                + esDomainName
                + " is not to the public due to using a VPC, Cognito, or any additional conditions within the resource policy.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on protecting Domains with a Resource-based Policy refer to the Identity and Access Management in Amazon Elasticsearch Service section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-ac.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsOpenSearchServiceDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsOpenSearchServiceDomain": {
                                "Id": domainId,
                                "DomainName": esDomainName,
                                "EngineVersion": esVersion
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-3",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-17",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-20",
                        "NIST SP 800-53 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding