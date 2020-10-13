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
def dedicated_master_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
                "Title": "[Elasticsearch.1] Elasticsearch Service domains should use dedicated master nodes",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " does not use dedicated master nodes. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should dedicated master nodes enabled refer to the Configuring Amazon ES Domains section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomains-configure-cluster",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
                "Title": "[Elasticsearch.1] Elasticsearch Service domains should use dedicated master nodes",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " uses dedicated master nodes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should dedicated master nodes enabled refer to the Configuring Amazon ES Domains section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomains-configure-cluster",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
    response = list_domain_names(cache)
    myDomainNames = response["DomainNames"]
    for domains in myDomainNames:
        esDomainName = str(domains["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomainName)
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        domainId = str(response["DomainStatus"]["DomainId"])
        domainArn = str(response["DomainStatus"]["ARN"])
        cognitoEnabledCheck = str(response["DomainStatus"]["CognitoOptions"]["Enabled"])
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
                "Title": "[Elasticsearch.2] Elasticsearch Service domains should use Cognito authentication for Kibana",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " does not use Cognito authentication for Kibana. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should use Cognito authentication for Kibana refer to the Amazon Cognito Authentication for Kibana section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
                "Title": "[Elasticsearch.2] Elasticsearch Service domains should use Cognito authentication for Kibana",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " uses Cognito authentication for Kibana.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should use Cognito authentication for Kibana refer to the Amazon Cognito Authentication for Kibana section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
def encryption_at_rest_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
                "Title": "[Elasticsearch.3] Elasticsearch Service domains should be encrypted at rest",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " is not encrypted at rest. You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 5.1 or later",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 5.1 or later.",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html#enabling-ear",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
                "Title": "[Elasticsearch.3] Elasticsearch Service domains should be encrypted at rest",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " is encrypted at rest",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 5.1 or later.",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html#enabling-ear",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
def node2node_encryption_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
                "Title": "[Elasticsearch.4] Elasticsearch Service domains should use node-to-node encryption",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " does not use node-to-node encryption. You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 6.0 or later",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 6.0 or later.",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
                "Title": "[Elasticsearch.4] Elasticsearch Service domains should use node-to-node encryption",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " uses node-to-node encryption.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot configure existing domains to use the feature. To enable the feature, you must create another domain and migrate your data. Encryption of data at rest requires Elasticsearch 6.0 or later.",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
def https_enforcement_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
                "Title": "[Elasticsearch.5] Elasticsearch Service domains should enforce HTTPS-only communications",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " does not enforce HTTPS-only communications. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should enforce HTTPS-only communications refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
                "Title": "[Elasticsearch.5] Elasticsearch Service domains should enforce HTTPS-only communications",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " enforces HTTPS-only communications. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your domain should enforce HTTPS-only communications refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
                    "Title": "[Elasticsearch.6] Elasticsearch Service domains that enforce HTTPS-only communications should use a TLS 1.2 security policy",
                    "Description": "Elasticsearch Service domain "
                    + esDomainName
                    + " does not use a TLS 1.2 security policy. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your domain should use a TLS 1.2 security policy refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsElasticsearchDomain",
                            "Id": domainArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsElasticsearchDomain": {
                                    "DomainId": domainId,
                                    "DomainName": esDomainName,
                                    "ElasticsearchVersion": esVersion,
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
                    "Title": "[Elasticsearch.6] Elasticsearch Service domains that enforce HTTPS-only communications should use a TLS 1.2 security policy",
                    "Description": "Elasticsearch Service domain "
                    + esDomainName
                    + " uses a TLS 1.2 security policy.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your domain should use a TLS 1.2 security policy refer to the About Configuration Changes section of the Amazon Elasticsearch Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-configuration-changes",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsElasticsearchDomain",
                            "Id": domainArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsElasticsearchDomain": {
                                    "DomainId": domainId,
                                    "DomainName": esDomainName,
                                    "ElasticsearchVersion": esVersion,
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
def elastic_update_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Elasticsearch.7] Elasticsearch Service domains should be updated to the latest service software version",
                "Description": "Elasticsearch Service domain "
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
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
                "Title": "[Elasticsearch.7] Elasticsearch Service domains should be updated to the latest service software version",
                "Description": "Elasticsearch Service domain "
                + esDomainName
                + " is up to date. Service provided message follows: "
                + updateInformation,
                "Remediation": {
                    "Recommendation": {
                        "Text": "For update information refer to the Service Software Updates section of the Amazon Elasticsearch Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-service-software",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsElasticsearchDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElasticsearchDomain": {
                                "DomainId": domainId,
                                "DomainName": esDomainName,
                                "ElasticsearchVersion": esVersion,
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
