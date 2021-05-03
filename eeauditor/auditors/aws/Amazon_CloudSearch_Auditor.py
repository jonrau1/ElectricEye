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

cloudsearch = boto3.client("cloudsearch")

@registry.register_check("cloudsearch")
def cloudsearch_https_enforcement_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudSearch.1] CloudSearch Domains should be configured to use enforce HTTPS-only communications"""
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # If you have one of these you're probably old as dirt lol
    for domain in cloudsearch.describe_domains()["DomainStatusList"]:
        dArn = str(domain["ARN"])
        dId = str(domain["DomainId"])
        dName = str(domain["DomainName"])
        # Check status
        response = cloudsearch.describe_domain_endpoint_options(DomainName=dName)["DomainEndpointOptions"]
        if str(response["Options"]["EnforceHTTPS"]) == "False":
            # create Sec Hub finding
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": dArn + "/cloudsearch-https-enforcement-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": dArn,
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
                "Title": "[CloudSearch.1] CloudSearch Domains should be configured to use enforce HTTPS-only communications",
                "Description": "CloudSearch Domain "
                + dName
                + " is not configured to enforce HTTPS-only communications to the Domain. Amazon CloudSearch domains let you require that all traffic to the domain arrive over HTTPS. This security feature helps you block clients that send unencrypted requests to the domain. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to enforce HTTPS refer to the Configuring Domain Endpoint Options in Amazon CloudSearch section of the Amazon CloudSearch Developer Guide",
                        "Url": "https://docs.aws.amazon.com/cloudsearch/latest/developerguide/configuring-domain-endpoint-options.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudSearchDomain",
                        "Id": dArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DomainArn": dArn,
                                "DomainId": dId,
                                "DomainName": dName
                            }
                        }
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
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # create Sec Hub finding
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": dArn + "/cloudsearch-https-enforcement-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": dArn,
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
                "Title": "[CloudSearch.1] CloudSearch Domains should be configured to use enforce HTTPS-only communications",
                "Description": "CloudSearch Domain "
                + dName
                + " is configured to enforce HTTPS-only communications to the Domain.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to enforce HTTPS refer to the Configuring Domain Endpoint Options in Amazon CloudSearch section of the Amazon CloudSearch Developer Guide",
                        "Url": "https://docs.aws.amazon.com/cloudsearch/latest/developerguide/configuring-domain-endpoint-options.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudSearchDomain",
                        "Id": dArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DomainArn": dArn,
                                "DomainId": dId,
                                "DomainName": dName
                            }
                        }
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
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudsearch")
def cloudsearch_tls1dot2_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudSearch.2] CloudSearch Domains that enforce HTTPS-only communications should use TLS 1.2 cipher suites"""
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # If you have one of these you're probably old as dirt lol
    for domain in cloudsearch.describe_domains()["DomainStatusList"]:
        dArn = str(domain["ARN"])
        dId = str(domain["DomainId"])
        dName = str(domain["DomainName"])
        # Check status
        response = cloudsearch.describe_domain_endpoint_options(DomainName=dName)["DomainEndpointOptions"]
        if str(response["Options"]["EnforceHTTPS"]) == "True":
            # This is a failing finding
            if str(response["Options"]["TLSSecurityPolicy"]) != "Policy-Min-TLS-1-2-2019-07":
                # create Sec Hub finding
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": dArn + "/cloudsearch-tls1dot2-policy-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": dArn,
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
                    "Title": "[CloudSearch.2] CloudSearch Domains that enforce HTTPS-only communications should use TLS 1.2 cipher suites",
                    "Description": "CloudSearch Domain "
                    + dName
                    + " does not use TLS 1.2 cipher suites. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn how to enforce HTTPS refer to the Configuring Domain Endpoint Options in Amazon CloudSearch section of the Amazon CloudSearch Developer Guide",
                            "Url": "https://docs.aws.amazon.com/cloudsearch/latest/developerguide/configuring-domain-endpoint-options.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsCloudSearchDomain",
                            "Id": dArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "DomainArn": dArn,
                                    "DomainId": dId,
                                    "DomainName": dName
                                }
                            }
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
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                # create Sec Hub finding
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": dArn + "/cloudsearch-tls1dot2-policy-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": dArn,
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
                    "Title": "[CloudSearch.2] CloudSearch Domains that enforce HTTPS-only communications should use TLS 1.2 cipher suites",
                    "Description": "CloudSearch Domain "
                    + dName
                    + " uses TLS 1.2 cipher suites.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn how to enforce HTTPS refer to the Configuring Domain Endpoint Options in Amazon CloudSearch section of the Amazon CloudSearch Developer Guide",
                            "Url": "https://docs.aws.amazon.com/cloudsearch/latest/developerguide/configuring-domain-endpoint-options.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsCloudSearchDomain",
                            "Id": dArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "DomainArn": dArn,
                                    "DomainId": dId,
                                    "DomainName": dName
                                }
                            }
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
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        else:
            continue