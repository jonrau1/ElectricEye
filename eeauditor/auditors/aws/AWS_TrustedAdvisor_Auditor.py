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

from check_register import CheckRegister
from botocore.exceptions import ClientError
import datetime
import base64
import json

registry = CheckRegister()

def describe_trusted_advisor_checks(cache, session):
    response = cache.get("describe_trusted_advisor_checks")
    if response:
        return response
    
    support = session.client("support", region_name="us-east-1")
    
    try:
        taChecks = []
        for check in support.describe_trusted_advisor_checks(language='en')["checks"]:
            check["result"] = support.describe_trusted_advisor_check_result(checkId=check["id"])["result"]
            taChecks.append(
                check
            )
        cache["describe_trusted_advisor_checks"] = taChecks
        return cache["describe_trusted_advisor_checks"]
    except ClientError:
        print("Not subscribed to AWS Premium Support!")
        return [] 

@registry.register_check("support")
def trusted_advisor_failing_cloudfront_ssl_cert_iam_certificate_store_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[TrustedAdvisor.1] AWS Trusted Advisor check results for CloudFront Custom SSL Certificates in the IAM Certificate Store should be investigated"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Use a list comprehension to get the specific Check we care about and generate vars and determining pass/fail
    filteredCheck = [check for check in describe_trusted_advisor_checks(cache, session) if check["name"] == "CloudFront Custom SSL Certificates in the IAM Certificate Store"][0]
    checkId = filteredCheck["id"]
    category = filteredCheck["category"]
    checkArn = f"arn:{awsPartition}:trustedadvisor:{awsRegion}:{awsAccountId}/{category}/{checkId}"
    assetJson = json.dumps(filteredCheck,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    # Logic time, mothafucka!
    if filteredCheck["result"]["resourcesSummary"]["resourcesFlagged"] >= 1:
        failingCheck = True
    else:
        failingCheck = False
        
    # this is a failing check
    if failingCheck is True:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{checkArn}/trusted-advisor-failing-cloudfront-ssl-cert-iam-cert-store-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{checkArn}/trusted-advisor-failing-cloudfront-ssl-cert-iam-cert-store-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[TrustedAdvisor.1] AWS Trusted Advisor check results for CloudFront Custom SSL Certificates in the IAM Certificate Store should be investigated",
            "Description": f"AWS Trusted Advisor check for CloudFront Custom SSL Certificates in the IAM Certificate Store with a Check Id of {checkId} has failed. Trusted Advisor checks the SSL certificates for CloudFront alternate domain names in the IAM certificate store and alerts you if the certificate is expired, will soon expire, uses outdated encryption, or is not configured correctly for the distribution. When a custom certificate for an alternate domain name expires, browsers that display your CloudFront content might show a warning message about the security of your website. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about setting up HTTPS for CloudFront refer to the Using HTTPS with CloudFront section of the Amazon CloudFront Developer Guide.",
                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Trusted Advisor",
                "AssetComponent": "Check"
            },
            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
            "Resources": [
                {
                    "Type": "AwsTrustedAdvisorCheck",
                    "Id": checkArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
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
                    "ISO 27001:2013 A.14.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    # this is a passing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{checkArn}/trusted-advisor-failing-cloudfront-ssl-cert-iam-cert-store-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{checkArn}/trusted-advisor-failing-cloudfront-ssl-cert-iam-cert-store-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[TrustedAdvisor.1] AWS Trusted Advisor check results for CloudFront Custom SSL Certificates in the IAM Certificate Store should be investigated",
            "Description": f"AWS Trusted Advisor check for CloudFront Custom SSL Certificates in the IAM Certificate Store with a Check Id of {checkId} is passing.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about setting up HTTPS for CloudFront refer to the Using HTTPS with CloudFront section of the Amazon CloudFront Developer Guide.",
                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Trusted Advisor",
                "AssetComponent": "Check"
            },
            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
            "Resources": [
                {
                    "Type": "AwsTrustedAdvisorCheck",
                    "Id": checkArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
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
                    "ISO 27001:2013 A.14.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("support")
def trusted_advisor_failing_cloudfront_ssl_cert_on_origin_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[TrustedAdvisor.2] AWS Trusted Advisor check results for CloudFront SSL Certificate on the Origin Server should be investigated"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Use a list comprehension to get the specific Check we care about and generate vars and determining pass/fail
    filteredCheck = [check for check in describe_trusted_advisor_checks(cache, session) if check["name"] == "CloudFront SSL Certificate on the Origin Server"][0]
    checkId = filteredCheck["id"]
    category = filteredCheck["category"]
    checkArn = f"arn:{awsPartition}:trustedadvisor:{awsRegion}:{awsAccountId}/{category}/{checkId}"
    assetJson = json.dumps(filteredCheck,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    # Logic time, mothafucka!
    if filteredCheck["result"]["resourcesSummary"]["resourcesFlagged"] >= 1:
        failingCheck = True
    else:
        failingCheck = False
        
    # this is a failing check
    if failingCheck is True:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{checkArn}/trusted-advisor-failing-cloudfront-ssl-origin-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{checkArn}/trusted-advisor-failing-cloudfront-ssl-origin-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[TrustedAdvisor.2] AWS Trusted Advisor check results for CloudFront SSL Certificate on the Origin Server should be investigated",
            "Description": f"AWS Trusted Advisor check for CloudFront SSL Certificate on the Origin Server with a Check Id of {checkId} has failed. Trusted Advisor checks your origin server for SSL certificates that are expired, about to expire, missing, or that use outdated encryption. If a certificate is expired, CloudFront responds to requests for your content with HTTP status code 502, Bad Gateway. Certificates that were encrypted by using the SHA-1 hashing algorithm are being deprecated by web browsers such as Chrome and Firefox. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about setting up HTTPS for CloudFront refer to the Using HTTPS with CloudFront section of the Amazon CloudFront Developer Guide.",
                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Trusted Advisor",
                "AssetComponent": "Check"
            },
            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
            "Resources": [
                {
                    "Type": "AwsTrustedAdvisorCheck",
                    "Id": checkArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
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
                    "ISO 27001:2013 A.14.1.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    # this is a passing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{checkArn}/trusted-advisor-failing-cloudfront-ssl-origin-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{checkArn}/trusted-advisor-failing-cloudfront-ssl-origin-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[TrustedAdvisor.2] AWS Trusted Advisor check results for CloudFront SSL Certificate on the Origin Server should be investigated",
            "Description": f"AWS Trusted Advisor check for CloudFront SSL Certificate on the Origin Server with a Check Id of {checkId} is passing.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about setting up HTTPS for CloudFront refer to the Using HTTPS with CloudFront section of the Amazon CloudFront Developer Guide.",
                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Trusted Advisor",
                "AssetComponent": "Check"
            },
            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
            "Resources": [
                {
                    "Type": "AwsTrustedAdvisorCheck",
                    "Id": checkArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
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
                    "ISO 27001:2013 A.14.1.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("support")
def trusted_advisor_failing_exposed_access_keys_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[TrustedAdvisor.3] AWS Trusted Advisor check results for Exposed Access Keys should be investigated"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Use a list comprehension to get the specific Check we care about and generate vars and determining pass/fail
    filteredCheck = [check for check in describe_trusted_advisor_checks(cache, session) if check["name"] == "Exposed Access Keys"][0]
    checkId = filteredCheck["id"]
    category = filteredCheck["category"]
    checkArn = f"arn:{awsPartition}:trustedadvisor:{awsRegion}:{awsAccountId}/{category}/{checkId}"
    assetJson = json.dumps(filteredCheck,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    # Logic time, mothafucka!
    if filteredCheck["result"]["resourcesSummary"]["resourcesFlagged"] >= 1:
        failingCheck = True
    else:
        failingCheck = False
        
    # this is a failing check
    if failingCheck is True:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{checkArn}/trusted-advisor-expose-iam-keys-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{checkArn}/trusted-advisor-expose-iam-keys-check",
            "AwsAccountId": awsAccountId,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices",
                "Effects/Data Exposure",
            ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "CRITICAL"},
            "Confidence": 99,
            "Title": "[TrustedAdvisor.3] AWS Trusted Advisor check results for Exposed Access Keys should be investigated",
            "Description": f"AWS Trusted Advisor check for Exposed Access Keys with a Check Id of {checkId} has failed. Trusted Advisor checks popular code repositories for access keys that have been exposed to the public and for irregular Amazon Elastic Compute Cloud (Amazon EC2) usage that could be the result of a compromised access key. An access key consists of an access key ID and the corresponding secret access key. Exposed access keys pose a security risk to your account and other users. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about rotating access keys refer to the Managing access keys for IAM users section of the AWS Identity and Access Management User Guide.",
                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Trusted Advisor",
                "AssetComponent": "Check"
            },
            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
            "Resources": [
                {
                    "Type": "AwsTrustedAdvisorCheck",
                    "Id": checkArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.2",
                    "ISO 27001:2013 A.9.2.1",
                    "ISO 27001:2013 A.9.2.2",
                    "ISO 27001:2013 A.9.2.3",
                    "ISO 27001:2013 A.9.2.4",
                    "ISO 27001:2013 A.9.2.6",
                    "ISO 27001:2013 A.9.3.1",
                    "ISO 27001:2013 A.9.4.2",
                    "ISO 27001:2013 A.9.4.3"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    # this is a passing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{checkArn}/trusted-advisor-expose-iam-keys-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{checkArn}/trusted-advisor-expose-iam-keys-check",
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
            "Title": "[TrustedAdvisor.3] AWS Trusted Advisor check results for Exposed Access Keys should be investigated",
            "Description": f"AWS Trusted Advisor check for Exposed Access Keys with a Check Id of {checkId} has failed. Trusted Advisor checks popular code repositories for access keys that have been exposed to the public and for irregular Amazon Elastic Compute Cloud (Amazon EC2) usage that could be the result of a compromised access key. An access key consists of an access key ID and the corresponding secret access key. Exposed access keys pose a security risk to your account and other users. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about rotating access keys refer to the Managing access keys for IAM users section of the AWS Identity and Access Management User Guide.",
                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Trusted Advisor",
                "AssetComponent": "Check"
            },
            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
            "Resources": [
                {
                    "Type": "AwsTrustedAdvisorCheck",
                    "Id": checkArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-1",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-3",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-6",
                    "NIST SP 800-53 Rev. 4 IA-7",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 IA-9",
                    "NIST SP 800-53 Rev. 4 IA-10",
                    "NIST SP 800-53 Rev. 4 IA-11",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.2",
                    "ISO 27001:2013 A.9.2.1",
                    "ISO 27001:2013 A.9.2.2",
                    "ISO 27001:2013 A.9.2.3",
                    "ISO 27001:2013 A.9.2.4",
                    "ISO 27001:2013 A.9.2.6",
                    "ISO 27001:2013 A.9.3.1",
                    "ISO 27001:2013 A.9.4.2",
                    "ISO 27001:2013 A.9.4.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

## end?