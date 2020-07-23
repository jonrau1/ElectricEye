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
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
elasticache = boto3.client("elasticache")


@registry.register_check("elasticache")
def redis_auth_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    # loop through EC clusters
    response = elasticache.describe_cache_clusters(MaxRecords=100)
    myElasticacheClusters = response["CacheClusters"]
    for clusters in myElasticacheClusters:
        clusterId = str(clusters["CacheClusterId"])
        clusterEngine = str(clusters["Engine"])
        # ignore memcached clusters
        if clusterEngine != "redis":
            pass
        else:
            engineVersion = str(clusters["EngineVersion"])
            # check for auth token
            authTokenCheck = str(clusters["AuthTokenEnabled"])
            # ISO Time
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if authTokenCheck == "False":
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
                    + " does not have a Redis AUTH token enabled. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your cluster should have a Redis AUTH token refer to the Modifying the AUTH Token on an Existing ElastiCache for Redis Cluster section of the ElastiCache for Redis User Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html#auth-modifyng-token",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsElastiCacheCacheCluster",
                            "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
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
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsElastiCacheCacheCluster",
                            "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
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


@registry.register_check("elasticache")
def encryption_at_rest_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # loop through EC clusters
    response = elasticache.describe_cache_clusters(MaxRecords=100)
    myElasticacheClusters = response["CacheClusters"]
    for clusters in myElasticacheClusters:
        clusterId = str(clusters["CacheClusterId"])
        clusterEngine = str(clusters["Engine"])
        # ignore memcached clusters
        if clusterEngine != "redis":
            print("Memcached cluster found, skipping as it does not support encryption")
            pass
        else:
            engineVersion = str(clusters["EngineVersion"])
            # check for encryption at rest
            atRestEncryptionCheck = str(clusters["AtRestEncryptionEnabled"])
            # ISO Time
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if atRestEncryptionCheck == "False":
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
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsElastiCacheCacheCluster",
                            "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
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
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsElastiCacheCacheCluster",
                            "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
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


@registry.register_check("elasticache")
def encryption_in_transit_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # loop through EC clusters
    response = elasticache.describe_cache_clusters(MaxRecords=100)
    myElasticacheClusters = response["CacheClusters"]
    for clusters in myElasticacheClusters:
        clusterId = str(clusters["CacheClusterId"])
        clusterEngine = str(clusters["Engine"])
        # ignore memcached clusters
        if clusterEngine != "redis":
            print("Memcached cluster found, skipping as it does not support encryption")
            pass
        else:
            engineVersion = str(clusters["EngineVersion"])
            # check for encryption in transit
            inTransitEncryptionCheck = str(clusters["TransitEncryptionEnabled"])
            # ISO Time
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if inTransitEncryptionCheck == "False":
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
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsElastiCacheCacheCluster",
                            "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
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
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsElastiCacheCacheCluster",
                            "Id": f"arn:{awsPartition}:elasticache:{awsRegion}:{awsAccountId}:cluster:{clusterId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"ClusterId": clusterId, "EngineVersion": engineVersion,}
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
