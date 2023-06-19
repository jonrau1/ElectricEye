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

import tomli
import os
import sys
import boto3
import requests
import ipaddress
import datetime
import base64
import json
from botocore.exceptions import ClientError
from check_register import CheckRegister

registry = CheckRegister()

SHODAN_HOSTS_URL = "https://api.shodan.io/shodan/host/"

def get_shodan_api_key(cache):

    response = cache.get("get_shodan_api_key")
    if response:
        return response

    validCredLocations = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

    # Get the absolute path of the current directory
    currentDir = os.path.abspath(os.path.dirname(__file__))
    # Go two directories back to /eeauditor/
    twoBack = os.path.abspath(os.path.join(currentDir, "../../"))

    # TOML is located in /eeauditor/ directory
    tomlFile = f"{twoBack}/external_providers.toml"
    with open(tomlFile, "rb") as f:
        data = tomli.load(f)

    # Parse from [global] to determine credential location of PostgreSQL Password
    credLocation = data["global"]["credentials_location"]
    shodanCredValue = data["global"]["shodan_api_key_value"]
    if credLocation not in validCredLocations:
        print(f"Invalid option for [global.credLocation]. Must be one of {str(validCredLocations)}.")
        sys.exit(2)
    if not shodanCredValue:
        apiKey = None
    else:

        # Boto3 Clients
        ssm = boto3.client("ssm")
        asm = boto3.client("secretsmanager")

        # Retrieve API Key
        if credLocation == "CONFIG_FILE":
            apiKey = shodanCredValue

        # Retrieve the credential from SSM Parameter Store
        elif credLocation == "AWS_SSM":
            
            try:
                apiKey = ssm.get_parameter(
                    Name=shodanCredValue,
                    WithDecryption=True
                )["Parameter"]["Value"]
            except ClientError as e:
                print(f"Error retrieving API Key from SSM, skipping all Shodan checks, error: {e}")
                apiKey = None

        # Retrieve the credential from AWS Secrets Manager
        elif credLocation == "AWS_SECRETS_MANAGER":
            try:
                apiKey = asm.get_secret_value(
                    SecretId=shodanCredValue,
                )["SecretString"]
            except ClientError as e:
                print(f"Error retrieving API Key from ASM, skipping all Shodan checks, error: {e}")
                apiKey = None
        
    cache["get_shodan_api_key"] = apiKey
    return cache["get_shodan_api_key"]

def google_dns_resolver(target):
    """
    Accepts a Public DNS name and attempts to use Google's DNS A record resolver to determine an IP address
    """
    url = f"https://dns.google/resolve?name={target}&type=A"
    
    r = requests.get(url=url)
    if r.status_code != 200:
        return None
    else:
        for result in json.loads(r.text)["Answer"]:
            try:
                if not (
                    ipaddress.IPv4Address(result["data"]).is_private
                    or ipaddress.IPv4Address(result["data"]).is_loopback
                    or ipaddress.IPv4Address(result["data"]).is_link_local
                ):
                    return result["data"]
                else:
                    continue
            except ipaddress.AddressValueError:
                continue
        # if the loop terminates without any result return None
        return None

def describe_es_os_domains(cache, session):
    response = cache.get("list_domain_names")
    if response:
        return response
    
    elasticsearch = session.client("es")
    domainDetails = []

    for domain in elasticsearch.list_domain_names()["DomainNames"]:
        domainDetails.append(
            elasticsearch.describe_elasticsearch_domain(
                DomainName=domain
            )
        )

    cache["list_domain_names"] = domainDetails
    return cache["list_domain_names"]

@registry.register_check("es")
def aws_es_os_dedicated_master_node_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.1] OpenSearch/AWS ElasticSearch Service domains should use dedicated master nodes"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for response in describe_es_os_domains(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainName = response["DomainStatus"]["DomainName"]
        esVersion = response["DomainStatus"]["ElasticsearchVersion"]
        domainId = response["DomainStatus"]["DomainId"]
        domainArn = response["DomainStatus"]["ARN"]
        if response["DomainStatus"]["ElasticsearchClusterConfig"]["DedicatedMasterEnabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-dedicated-master-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-dedicated-master-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("es")
def aws_es_os_coginto_authentication_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.2] OpenSearch/AWS ElasticSearch Service domains should use Cognito authentication for Kibana"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for response in describe_es_os_domains(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainName = response["DomainStatus"]["DomainName"]
        esVersion = response["DomainStatus"]["ElasticsearchVersion"]
        domainId = response["DomainStatus"]["DomainId"]
        domainArn = response["DomainStatus"]["ARN"]
        try:
            cognitoEnabledCheck = response["DomainStatus"]["CognitoOptions"]["Enabled"]
        except:
            cognitoEnabledCheck = False
        # this is a failing check
        if cognitoEnabledCheck is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-cognito-auth-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-6",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 PE-2",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-cognito-auth-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-6",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 PE-2",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("es")
def aws_es_os_encryption_at_rest_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.3] OpenSearch/AWS ElasticSearch Service domains should be encrypted at rest"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for response in describe_es_os_domains(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainName = response["DomainStatus"]["DomainName"]
        esVersion = response["DomainStatus"]["ElasticsearchVersion"]
        domainId = response["DomainStatus"]["DomainId"]
        domainArn = response["DomainStatus"]["ARN"]
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if response["DomainStatus"]["EncryptionAtRestOptions"]["Enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-encryption-at-rest-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
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
                "Id": f"{domainArn}/elasticsearch-encryption-at-rest-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("es")
def aws_es_os_node2node_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.4] OpenSearch/AWS ElasticSearch Service domains should use node-to-node encryption"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for response in describe_es_os_domains(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainName = response["DomainStatus"]["DomainName"]
        esVersion = response["DomainStatus"]["ElasticsearchVersion"]
        domainId = response["DomainStatus"]["DomainId"]
        domainArn = response["DomainStatus"]["ARN"]
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if response["DomainStatus"]["NodeToNodeEncryptionOptions"]["Enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-node2node-encryption-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
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
                "Id": f"{domainArn}/elasticsearch-node2node-encryption-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
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
def aws_es_os_https_enforcement_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.5] OpenSearch/AWS ElasticSearch Service domains should enforce HTTPS-only communications"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for response in describe_es_os_domains(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainName = response["DomainStatus"]["DomainName"]
        esVersion = response["DomainStatus"]["ElasticsearchVersion"]
        domainId = response["DomainStatus"]["DomainId"]
        domainArn = response["DomainStatus"]["ARN"]
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if response["DomainStatus"]["DomainEndpointOptions"]["EnforceHTTPS"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-enforce-https-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
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
                "Id": f"{domainArn}/elasticsearch-enforce-https-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
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
def aws_es_os_tls_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.6] OpenSearch/AWS ElasticSearch Service domains that enforce HTTPS-only communications should use a TLS 1.2 security policy"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for response in describe_es_os_domains(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainName = response["DomainStatus"]["DomainName"]
        esVersion = response["DomainStatus"]["ElasticsearchVersion"]
        domainId = response["DomainStatus"]["DomainId"]
        domainArn = response["DomainStatus"]["ARN"]
        if response["DomainStatus"]["DomainEndpointOptions"]["EnforceHTTPS"] is True:
            tlsPolicyCheck = str(
                response["DomainStatus"]["DomainEndpointOptions"]["TLSSecurityPolicy"]
            )
            if response["DomainStatus"]["DomainEndpointOptions"]["TLSSecurityPolicy"] != "Policy-Min-TLS-1-2-2019-07":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{domainArn}/elasticsearch-tls-1-2-check",
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Analytics",
                        "AssetService": "Amazon OpenSearch Service",
                        "AssetComponent": "Search Domain"
                    },
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
                            "NIST CSF V1.1 PR.DS-2",
                            "NIST SP 800-53 Rev. 4 SC-8",
                            "NIST SP 800-53 Rev. 4 SC-11",
                            "NIST SP 800-53 Rev. 4 SC-12",
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
                    "Id": f"{domainArn}/elasticsearch-tls-1-2-check",
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Analytics",
                        "AssetService": "Amazon OpenSearch Service",
                        "AssetComponent": "Search Domain"
                    },
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
                            "NIST CSF V1.1 PR.DS-2",
                            "NIST SP 800-53 Rev. 4 SC-8",
                            "NIST SP 800-53 Rev. 4 SC-11",
                            "NIST SP 800-53 Rev. 4 SC-12",
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
            continue

@registry.register_check("es")
def aws_es_os_elastic_update_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.7] OpenSearch/AWS ElasticSearch Service domains should be updated to the latest service software version"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for response in describe_es_os_domains(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainName = response["DomainStatus"]["DomainName"]
        esVersion = response["DomainStatus"]["ElasticsearchVersion"]
        domainId = response["DomainStatus"]["DomainId"]
        domainArn = response["DomainStatus"]["ARN"]
        updateInformation = str(response["DomainStatus"]["ServiceSoftwareOptions"]["Description"])
        if response["DomainStatus"]["ServiceSoftwareOptions"]["UpdateAvailable"] is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-version-update-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-version-update-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("es")
def aws_elasticsearch_in_vpc_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.8] OpenSearch/AWS ElasticSearch Service domains should be in a VPC"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for response in describe_es_os_domains(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainName = response["DomainStatus"]["DomainName"]
        esVersion = response["DomainStatus"]["ElasticsearchVersion"]
        domainId = response["DomainStatus"]["DomainId"]
        domainArn = response["DomainStatus"]["ARN"]
        try:
            vpcId = str(response["VPCOptions"]["VPCId"])
        except KeyError:
            vpcId = "NO_VPC"
        # This is a failing check
        if vpcId == "NO_VPC":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-in-vpc-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-in-vpc-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("es")
def aws_elasticsearch_public_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.9] OpenSearch/AWS ElasticSearch Service domains should not be exposed to the public"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for response in describe_es_os_domains(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainName = response["DomainStatus"]["DomainName"]
        esVersion = response["DomainStatus"]["ElasticsearchVersion"]
        domainId = response["DomainStatus"]["DomainId"]
        domainArn = response["DomainStatus"]["ARN"]
        # Determine if ES has Cognito Enabled
        try:
            cognitoEnabledCheck = str(response["DomainStatus"]["CognitoOptions"]["Enabled"])
        except KeyError:
            cognitoEnabledCheck = False
        # Determine if ES is in a VPC
        try:
            vpcId = str(response["VPCOptions"]["VPCId"])
        except KeyError:
            vpcId = "NO_VPC"
        # Determine if there is a policy and then parse through it. If the "AWS": "*" principal is allowed (anonymous access) without
        # any conditions we can assume there is not anything else to stop them
        try:
            policyDoc = response["AccessPolicies"]
            policyJson = json.loads(policyDoc.encode().decode("unicode_escape"))
            hasPolicy = True
            for sid in policyJson["Statement"]:
                try:
                    conditionCheck = str(sid["Condition"])
                    hasCondition = True
                except:
                    conditionCheck = ""
                    hasCondition = False
                if str(sid["Principal"]) == '{"AWS": "*"}' and hasCondition is False:
                    policyAllowAnon = True
                else:
                    policyAllowAnon = False
        except KeyError or ValueError:
            policyDoc = ""
            policyJson = "NO_POLICY"
            policyAllowAnon = "NO_POLICY"
            hasPolicy = False
        # Full Public Check
        if policyAllowAnon is True and vpcId == "NO_VPC" and cognitoEnabledCheck is False:
            fullPublic = True
        else:
            fullPublic = False
        # This is a failing check
        if fullPublic is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-public-access-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{domainArn}/elasticsearch-public-access-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon OpenSearch Service",
                    "AssetComponent": "Search Domain"
                },
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
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("es")
def public_es_domain_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[OpenSearch.10] OpenSearch/ElasticSearch Service domains outside of a VPC should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key(cache)
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for response in describe_es_os_domains(cache, session):
        if shodanApiKey is None:
            continue
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainName = response["DomainStatus"]["DomainName"]
        esVersion = response["DomainStatus"]["ElasticsearchVersion"]
        domainId = response["DomainStatus"]["DomainId"]
        domainArn = response["DomainStatus"]["ARN"]
        # Determine if ES has Cognito Enabled
        try:
            cognitoEnabledCheck = str(response["DomainStatus"]["CognitoOptions"]["Enabled"])
        except KeyError:
            cognitoEnabledCheck = False
        # Determine if ES is in a VPC
        try:
            response["VPCOptions"]["VPCId"]
        except KeyError:
            vpcId = "NO_VPC"
        # Determine if there is a policy and then parse through it. If the "AWS": "*" principal is allowed (anonymous access) without
        # any conditions we can assume there is not anything else to stop them
        try:
            policyDoc = response["AccessPolicies"]
            policyJson = json.loads(policyDoc.encode().decode("unicode_escape"))
            hasPolicy = True
            for sid in policyJson["Statement"]:
                try:
                    conditionCheck = str(sid["Condition"])
                    hasCondition = True
                except:
                    conditionCheck = ""
                    hasCondition = False
                if str(sid["Principal"]) == '{"AWS": "*"}' and hasCondition is False:
                    policyAllowAnon = True
                else:
                    policyAllowAnon = False
        except KeyError or ValueError:
            policyDoc = ""
            policyJson = "NO_POLICY"
            policyAllowAnon = "NO_POLICY"
            hasPolicy = False
        # Full Public Check
        if policyAllowAnon is True and vpcId == "NO_VPC" and cognitoEnabledCheck is False:
            fullPublic = True
        else:
            fullPublic = False
        esDomainEndpoint = str(response["Endpoint"])

        # Now let's check Shodan
        if fullPublic is True:
            # Use Google DNS to resolve
            esDomainIp = google_dns_resolver(esDomainEndpoint)
            if esDomainIp is None:
                continue
            # check if IP indexed by Shodan
            r = requests.get(url=f"{SHODAN_HOSTS_URL}{esDomainIp}?key={shodanApiKey}").json()
            if str(r) == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{domainArn}/{esDomainEndpoint}/elasticsearch-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": domainArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[OpenSearch.10] OpenSearch/ElasticSearch Service domains outside of a VPC should be monitored for being indexed by Shodan",
                    "Description": f"OpenSearch/ElasticSearch Service domain {esDomainName} has not been indexed by Shodan.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": SHODAN_HOSTS_URL
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Analytics",
                        "AssetService": "Amazon OpenSearch Service",
                        "AssetComponent": "Search Domain"
                    },
                    "Resources": [
                        {
                            "Type": "AwsOpenSearchDomain",
                            "Id": domainArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsOpenSearchDomain": {
                                    "DomainId": hasPolicy,
                                    "DomainName": esDomainName,
                                    "ElasticsearchVersion": esVersion,
                                    "Endpoint": esDomainEndpoint,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                assetPayload = {
                    "Domain": response,
                    "Shodan": r
                }
                assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{domainArn}/{esDomainEndpoint}/elasticsearch-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": domainArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[OpenSearch.10] OpenSearch/ElasticSearch Service domains outside of a VPC should be monitored for being indexed by Shodan",
                    "Description": f"ElasticSearch/OpenSearch Service domain {esDomainName} has been indexed by Shodan on IP address on {esDomainIp} - resolved from endpoint DNS {esDomainEndpoint}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": f"{SHODAN_HOSTS_URL}{esDomainIp}"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Analytics",
                        "AssetService": "Amazon OpenSearch Service",
                        "AssetComponent": "Search Domain"
                    },
                    "Resources": [
                        {
                            "Type": "AwsElasticsearchDomain",
                            "Id": domainArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsElasticsearchDomain": {
                                    "DomainId": hasPolicy,
                                    "DomainName": esDomainName,
                                    "ElasticsearchVersion": esVersion,
                                    "Endpoint": esDomainEndpoint,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding

## END ??