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
import botocore
from check_register import CheckRegister

registry = CheckRegister()

def list_wafs(cache, session):
    wafv2 = session.client("wafv2")
    response = cache.get("list_web_acls")
    if response:
        return response
    cache["list_web_acls"] = wafv2.list_web_acls(Scope='REGIONAL')
    return cache["list_web_acls"]

def list_wafs_global(cache, session):
    globalWafv2 = session.client("wafv2", region_name="us-east-1")
    response = cache.get("list_web_acls")
    if response:
        return response
    cache["list_web_acls"] = globalWafv2.list_web_acls(Scope='CLOUDFRONT')
    return cache["list_web_acls"]

@registry.register_check("wafv2")
def wafv2_web_acl_metrics_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[WAFv2.1] WAFv2 Web ACLs should have CloudWatch Metrics enabled"""
    wafv2 = session.client("wafv2")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for w in list_wafs(cache, session)["WebACLs"]:
        wafArn = str(w["ARN"])
        wafId = str(w["Id"])
        wafName = str(w["Name"])
        # Get WAF Details
        waf = wafv2.get_web_acl(Name=wafName,Scope='REGIONAL',Id=wafId)["WebACL"]
        # This is a failing check
        if str(waf["VisibilityConfig"]["CloudWatchMetricsEnabled"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": wafArn + "/webacl-metrics-enabled-regional-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": wafArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[WAFv2.1] WAFv2 Web ACLs should have CloudWatch Metrics enabled",
                "Description": "AWS WAFv2 Web ACL "
                + wafName
                + " does not have CloudWatch Metrics enabled, you can use statistics in Amazon CloudWatch to gain a perspective on how your web application or service is performing. Web ACLs created by Firewall Manager do not have Metrics enabled by default. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about WAFv2 Metrics refer to the Monitoring with Amazon CloudWatch section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#metrics_dimensions"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWafWebAcl",
                        "Id": wafArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsWafWebAcl": {
                                "Name": wafName,
                                "WebAclId": wafId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": wafArn + "/webacl-metrics-enabled-regional-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": wafArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[WAFv2.1] WAFv2 Web ACLs should have CloudWatch Metrics enabled",
                "Description": "AWS WAFv2 Web ACL "
                + wafName
                + " has CloudWatch Metrics enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about WAFv2 Metrics refer to the Monitoring with Amazon CloudWatch section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#metrics_dimensions"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWafWebAcl",
                        "Id": wafArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsWafWebAcl": {
                                "Name": wafName,
                                "WebAclId": wafId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("wafv2")
def wafv2_web_acl_sampling_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[WAFv2.2] WAFv2 Web ACLs should have Request Sampling enabled"""
    wafv2 = session.client("wafv2")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for w in list_wafs(cache, session)["WebACLs"]:
        wafArn = str(w["ARN"])
        wafId = str(w["Id"])
        wafName = str(w["Name"])
        # Get WAF Details
        waf = wafv2.get_web_acl(Name=wafName,Scope='REGIONAL',Id=wafId)["WebACL"]
        # This is a failing check
        if str(waf["VisibilityConfig"]["SampledRequestsEnabled"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": wafArn + "/webacl-request-sampling-enabled-regional-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": wafArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[WAFv2.2] WAFv2 Web ACLs should have Request Sampling enabled",
                "Description": "AWS WAFv2 Web ACL "
                + wafName
                + " does not have Request Sampling enabled, if you have request sampling enabled, you can view a sample of the requests that an associated resource has forwarded to AWS WAF for inspection. For each sampled request, you can view detailed data about the request, such as the originating IP address and the headers included in the request. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about WAFv2 Request Sampling refer to the Testing web ACLs section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html#web-acl-testing-view-sample"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWafWebAcl",
                        "Id": wafArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsWafWebAcl": {
                                "Name": wafName,
                                "WebAclId": wafId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": wafArn + "/webacl-request-sampling-enabled-regional-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": wafArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[WAFv2.2] WAFv2 Web ACLs should have Request Sampling enabled",
                "Description": "AWS WAFv2 Web ACL "
                + wafName
                + " has Request Sampling enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about WAFv2 Request Sampling refer to the Testing web ACLs section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html#web-acl-testing-view-sample"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWafWebAcl",
                        "Id": wafArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsWafWebAcl": {
                                "Name": wafName,
                                "WebAclId": wafId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("wafv2")
def wafv2_web_acl_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[WAFv2.3] WAFv2 Web ACLs should have Logging enabled"""
    wafv2 = session.client("wafv2")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for w in list_wafs(cache, session)["WebACLs"]:
        wafArn = str(w["ARN"])
        wafId = str(w["Id"])
        wafName = str(w["Name"])
        try:
            # This is a passing check
            wafv2.get_logging_configuration(ResourceArn=wafArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": wafArn + "/webacl-logging-enabled-regional-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": wafArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[WAFv2.3] WAFv2 Web ACLs should have Logging enabled",
                "Description": "AWS WAFv2 Web ACL "
                + wafName
                + " has Logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about WAFv2 Logging refer to the Logging web ACL traffic information section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/logging.html#logging-management"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWafWebAcl",
                        "Id": wafArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsWafWebAcl": {
                                "Name": wafName,
                                "WebAclId": wafId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'WAFNonexistentItemException':
                # this is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": wafArn + "/webacl-logging-enabled-regional-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": wafArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[WAFv2.3] WAFv2 Web ACLs should have Logging enabled",
                    "Description": "AWS WAFv2 Web ACL "
                    + wafName
                    + " does not have Logging enabled, if you have logging enabled, you can get detailed information about traffic that is analyzed by your web ACL. Information that is contained in the logs includes the time that AWS WAF received the request from your AWS resource, detailed information about the request, and the action for the rule that each request matched. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about WAFv2 Logging refer to the Logging web ACL traffic information section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                            "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/logging.html#logging-management"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsWafWebAcl",
                            "Id": wafArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsWafWebAcl": {
                                    "Name": wafName,
                                    "WebAclId": wafId
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF DE.AE-3",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 CA-7",
                            "NIST SP 800-53 IR-4",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-8",
                            "NIST SP 800-53 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                print(error)

### These following checks are mirrored for the "Global" WAF for CloudFront (for now) - the Global Endpoint is only available in us-east-1

@registry.register_check("wafv2")
def wafv2_web_acl_global_metrics_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[WAFv2.4] WAFv2 Global Web ACLs should have CloudWatch Metrics enabled"""
    globalWafv2 = session.client("wafv2", region_name="us-east-1")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for w in list_wafs_global(cache, session)["WebACLs"]:
        wafArn = str(w["ARN"])
        wafId = str(w["Id"])
        wafName = str(w["Name"])
        # Get WAF Details
        waf = globalWafv2.get_web_acl(Name=wafName,Scope='CLOUDFRONT',Id=wafId)["WebACL"]
        # This is a failing check
        if str(waf["VisibilityConfig"]["CloudWatchMetricsEnabled"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": wafArn + "/webacl-metrics-enabled-global-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": wafArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[WAFv2.4] WAFv2 Global Web ACLs should have CloudWatch Metrics enabled",
                "Description": "AWS WAFv2 Web ACL "
                + wafName
                + " does not have CloudWatch Metrics enabled, you can use statistics in Amazon CloudWatch to gain a perspective on how your web application or service is performing. Web ACLs created by Firewall Manager do not have Metrics enabled by default. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about WAFv2 Metrics refer to the Monitoring with Amazon CloudWatch section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#metrics_dimensions"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWafWebAcl",
                        "Id": wafArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsWafWebAcl": {
                                "Name": wafName,
                                "WebAclId": wafId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": wafArn + "/webacl-metrics-enabled-global-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": wafArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[WAFv2.4] WAFv2 Global Web ACLs should have CloudWatch Metrics enabled",
                "Description": "AWS WAFv2 Web ACL "
                + wafName
                + " has CloudWatch Metrics enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about WAFv2 Metrics refer to the Monitoring with Amazon CloudWatch section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#metrics_dimensions"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWafWebAcl",
                        "Id": wafArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsWafWebAcl": {
                                "Name": wafName,
                                "WebAclId": wafId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("wafv2")
def wafv2_web_acl_global_sampling_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[WAFv2.5] WAFv2 Global Web ACLs should have Request Sampling enabled"""
    globalWafv2 = session.client("wafv2", region_name="us-east-1")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for w in list_wafs_global(cache, session)["WebACLs"]:
        wafArn = str(w["ARN"])
        wafId = str(w["Id"])
        wafName = str(w["Name"])
        # Get WAF Details
        waf = globalWafv2.get_web_acl(Name=wafName,Scope='CLOUDFRONT',Id=wafId)["WebACL"]
        # This is a failing check
        if str(waf["VisibilityConfig"]["SampledRequestsEnabled"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": wafArn + "/webacl-request-sampling-enabled-global-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": wafArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[WAFv2.5] WAFv2 Global Web ACLs should have Request Sampling enabled",
                "Description": "AWS WAFv2 Web ACL "
                + wafName
                + " does not have Request Sampling enabled, if you have request sampling enabled, you can view a sample of the requests that an associated resource has forwarded to AWS WAF for inspection. For each sampled request, you can view detailed data about the request, such as the originating IP address and the headers included in the request. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about WAFv2 Request Sampling refer to the Testing web ACLs section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html#web-acl-testing-view-sample"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWafWebAcl",
                        "Id": wafArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsWafWebAcl": {
                                "Name": wafName,
                                "WebAclId": wafId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": wafArn + "/webacl-request-sampling-enabled-global-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": wafArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[WAFv2.5] WAFv2 Global Web ACLs should have Request Sampling enabled",
                "Description": "AWS WAFv2 Web ACL "
                + wafName
                + " has Request Sampling enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about WAFv2 Request Sampling refer to the Testing web ACLs section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html#web-acl-testing-view-sample"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWafWebAcl",
                        "Id": wafArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsWafWebAcl": {
                                "Name": wafName,
                                "WebAclId": wafId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("wafv2")
def wafv2_web_acl_global_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[WAFv2.6] WAFv2 Global Web ACLs should have Logging enabled"""
    globalWafv2 = session.client("wafv2", region_name="us-east-1")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for w in list_wafs_global(cache, session)["WebACLs"]:
        wafArn = str(w["ARN"])
        wafId = str(w["Id"])
        wafName = str(w["Name"])
        try:
            # This is a passing check
            globalWafv2.get_logging_configuration(ResourceArn=wafArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": wafArn + "/webacl-logging-enabled-global-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": wafArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[WAFv2.6] WAFv2 Global Web ACLs should have Logging enabled",
                "Description": "AWS WAFv2 Web ACL "
                + wafName
                + " has Logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about WAFv2 Logging refer to the Logging web ACL traffic information section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/logging.html#logging-management"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWafWebAcl",
                        "Id": wafArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsWafWebAcl": {
                                "Name": wafName,
                                "WebAclId": wafId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'WAFNonexistentItemException':
                # this is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": wafArn + "/webacl-logging-enabled-global-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": wafArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[WAFv2.6] WAFv2 Global Web ACLs should have Logging enabled",
                    "Description": "AWS WAFv2 Web ACL "
                    + wafName
                    + " does not have Logging enabled, if you have logging enabled, you can get detailed information about traffic that is analyzed by your web ACL. Information that is contained in the logs includes the time that AWS WAF received the request from your AWS resource, detailed information about the request, and the action for the rule that each request matched. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about WAFv2 Logging refer to the Logging web ACL traffic information section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                            "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/logging.html#logging-management"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsWafWebAcl",
                            "Id": wafArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsWafWebAcl": {
                                    "Name": wafName,
                                    "WebAclId": wafId
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF DE.AE-3",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 CA-7",
                            "NIST SP 800-53 IR-4",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-8",
                            "NIST SP 800-53 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding