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

import datetime
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

def get_redis_cache_clusters(cache, session):
    elasticache = session.client("elasticache")
    # Write only Redis clusters
    redisCacheClusters = []

    response = cache.get("get_redis_cache_clusters")
    if response:
        return response
    
    for cluster in elasticache.describe_cache_clusters(MaxRecords=100)["CacheClusters"]:
        if cluster["Engine"] == "redis":
            redisCacheClusters.append(cluster)            

    cache["get_redis_cache_clusters"] = redisCacheClusters
    return cache["get_redis_cache_clusters"]

def get_memcached_cache_clusters(cache, session):
    elasticache = session.client("elasticache")
    # Write only Memcached clusters
    memcachedCacheClusters = []

    response = cache.get("get_memcached_cache_clusters")
    if response:
        return response
    
    for cluster in elasticache.describe_cache_clusters(MaxRecords=100)["CacheClusters"]:
        if cluster["Engine"] == "memcached":
            memcachedCacheClusters.append(cluster)

    cache["get_memcached_cache_clusters"] = memcachedCacheClusters
    return cache["get_memcached_cache_clusters"]

@registry.register_check("elasticache")
def redis_auth_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Elasticache.Redis.1] Elasticache Redis clusters should have an AUTH token enabled"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for clusters in get_redis_cache_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clusters,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = str(clusters["CacheClusterId"])
        engineVersion = str(clusters["EngineVersion"])
        
        if clusters["AuthTokenEnabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterId + "/no-redis-auth-token",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterId,
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
                "Title": "[Elasticache.Redis.1] Elasticache Redis clusters should have an AUTH token enabled",
                "Description": "Elasticache cluster "
                + clusterId
                + " does not have a Redis AUTH token enabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should have a Redis AUTH token refer to the Modifying the AUTH Token on an Existing ElastiCache for Redis Cluster section of the ElastiCache for Redis User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html#auth-modifyng-token",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Amazon ElastiCache for Redis",
                    "AssetComponent": "Cache Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsElastiCacheCacheCluster",
                        "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion}
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
                        "ISO 27001:2013 A.9.2.1",
                        "CIS AWS Database Services Benchmark V1.0 5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterId + "/no-redis-auth-token",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterId,
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
                "Title": "[Elasticache.Redis.1] Elasticache Redis clusters should have an AUTH token enabled",
                "Description": "Elasticache cluster "
                + clusterId
                + " has a Redis AUTH token enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should have a Redis AUTH token refer to the Modifying the AUTH Token on an Existing ElastiCache for Redis Cluster section of the ElastiCache for Redis User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html#auth-modifyng-token",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Amazon ElastiCache for Redis",
                    "AssetComponent": "Cache Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsElastiCacheCacheCluster",
                        "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
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
                        "ISO 27001:2013 A.9.2.1",
                        "CIS AWS Database Services Benchmark V1.0 5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("elasticache")
def encryption_at_rest_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Elasticache.Redis.2] Elasticache Redis clusters should have encryption at rest enabled"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for clusters in get_redis_cache_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clusters,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = str(clusters["CacheClusterId"])
        engineVersion = str(clusters["EngineVersion"])
        if clusters["AtRestEncryptionEnabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterId + "/no-encryption-at-rest",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterId,
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
                "Title": "[Elasticache.Redis.2] Elasticache Redis clusters should have encryption at rest enabled",
                "Description": "Elasticache cluster "
                + clusterId
                + " does not have encryption at rest enabled. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should have encryption at rest enabled refer to the At-Rest Encryption in ElastiCache for Redis section of the ElastiCache for Redis User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html#at-rest-encryption-enable",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Amazon ElastiCache for Redis",
                    "AssetComponent": "Cache Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsElastiCacheCacheCluster",
                        "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
                        }
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
                        "CIS AWS Database Services Benchmark V1.0 5.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterId + "/no-encryption-at-rest",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterId,
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
                "Title": "[Elasticache.Redis.2] Elasticache Redis clusters should have encryption at rest enabled",
                "Description": "Elasticache cluster "
                + clusterId
                + " has encryption at rest enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should have encryption at rest enabled refer to the At-Rest Encryption in ElastiCache for Redis section of the ElastiCache for Redis User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html#at-rest-encryption-enable",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Amazon ElastiCache for Redis",
                    "AssetComponent": "Cache Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsElastiCacheCacheCluster",
                        "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
                        }
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
                        "CIS AWS Database Services Benchmark V1.0 5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("elasticache")
def encryption_in_transit_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Elasticache.Redis.3] Elasticache Redis clusters should have encryption in transit enabled"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for clusters in get_redis_cache_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clusters,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = str(clusters["CacheClusterId"])
        engineVersion = str(clusters["EngineVersion"])
        if clusters["TransitEncryptionEnabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterId + "/no-encryption-in-transit",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterId,
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
                "Title": "[Elasticache.Redis.3] Elasticache Redis clusters should have encryption in transit enabled",
                "Description": "Elasticache cluster "
                + clusterId
                + " does not have encryption in transit enabled. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should have encryption in transit enabled refer to the Enabling In-Transit Encryption section of the ElastiCache for Redis User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html#in-transit-encryption-enable",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Amazon ElastiCache for Redis",
                    "AssetComponent": "Cache Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsElastiCacheCacheCluster",
                        "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
                        }
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
                        "CIS AWS Database Services Benchmark V1.0 5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterId + "/no-encryption-in-transit",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterId,
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
                "Title": "[Elasticache.Redis.3] Elasticache Redis clusters should have encryption in transit enabled",
                "Description": "Elasticache cluster "
                + clusterId
                + " has encryption in transit enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your cluster should have encryption in transit enabled refer to the Enabling In-Transit Encryption section of the ElastiCache for Redis User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html#in-transit-encryption-enable",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Amazon ElastiCache for Redis",
                    "AssetComponent": "Cache Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsElastiCacheCacheCluster",
                        "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
                        }
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
                        "CIS AWS Database Services Benchmark V1.0 5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding


# EOF