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
import botocore
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients
support = boto3.client("support")

# loop through WAFs
def describe_trusted_advisor_checks(cache):
    response = cache.get("describe_trusted_advisor_checks")
    if response:
        return response
    cache["describe_trusted_advisor_checks"] = support.describe_trusted_advisor_checks(language='en')
    return cache["describe_trusted_advisor_checks"]

@registry.register_check("support")
def trusted_advisor_failing_root_mfa_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[TrustedAdvisor.1] Trusted Advisor check results for MFA on Root Account should be investigated"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if awsRegion == 'us-east-1':
        try:
            for t in describe_trusted_advisor_checks(cache=cache)["checks"]:
                if str(t["name"]) == "MFA on Root Account":
                    checkId = str(t["id"])
                    # this is a failing check
                    if int(support.describe_trusted_advisor_check_result(checkId=checkId)["result"]["resourcesSummary"]["resourcesFlagged"]) >= 1:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": awsAccountId + checkId + "/trusted-advisor-failing-root-mfa-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": awsAccountId + checkId,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "CRITICAL"},
                            "Confidence": 99,
                            "Title": "[TrustedAdvisor.1] Trusted Advisor check results for MFA on Root Account should be investigated",
                            "Description": "Trusted Advisor Check for MFA on Root Account with a Check Id of "
                            + checkId
                            + ". has failed. Trusted Advisor checks the root account and warns if multi-factor authentication (MFA) is not enabled. For increased security, we recommend that you protect your account by using MFA, which requires a user to enter a unique authentication code from their MFA hardware or virtual device when interacting with the AWS console and associated websites. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about setting up MFA refer to the Using multi-factor authentication (MFA) in AWS section of the AWS Identity and Access Management User Guide.",
                                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                            "Resources": [
                                {
                                    "Type": "AwsTrustedAdvisorCheck",
                                    "Id": checkId,
                                    "Partition": awsPartition,
                                    "Region": awsRegion
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
                            "Id": awsAccountId + checkId + "/trusted-advisor-failing-root-mfa-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": awsAccountId + checkId,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[TrustedAdvisor.1] Trusted Advisor check results for MFA on Root Account should be investigated",
                            "Description": "Trusted Advisor Check for MFA on Root Account with a Check Id of "
                            + checkId
                            + ". is passing.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about setting up MFA refer to the Using multi-factor authentication (MFA) in AWS section of the AWS Identity and Access Management User Guide.",
                                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                            "Resources": [
                                {
                                    "Type": "AwsTrustedAdvisorCheck",
                                    "Id": checkId,
                                    "Partition": awsPartition,
                                    "Region": awsRegion
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
                                    "ISO 27001:2013 A.9.4.3"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    break
                else:
                    continue
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('You are not subscribed to AWS Premium Support - cannot use the Trusted Advisor Auditor')
            else:
                print(error)
    else:
        print('AWS Health Global endpoint is located in us-east-1')

@registry.register_check("support")
def trusted_advisor_failing_elb_listener_security_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[TrustedAdvisor.2] Trusted Advisor check results for ELB Listener Security should be investigated"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if awsRegion == 'us-east-1':
        try:
            for t in describe_trusted_advisor_checks(cache=cache)["checks"]:
                if str(t["name"]) == "ELB Listener Security":
                    checkId = str(t["id"])
                    # this is a failing check
                    if int(support.describe_trusted_advisor_check_result(checkId=checkId)["result"]["resourcesSummary"]["resourcesFlagged"]) >= 1:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": awsAccountId + checkId + "/trusted-advisor-failing-elb-listener-security-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": awsAccountId + checkId,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[TrustedAdvisor.2] Trusted Advisor check results for ELB Listener Security should be investigated",
                            "Description": "Trusted Advisor Check for ELB Listener Security with a Check Id of "
                            + checkId
                            + ". has failed. Trusted Advisor checks for load balancers with listeners that do not use recommended security configurations for encrypted communication. AWS recommends using a secure protocol (HTTPS or SSL), up-to-date security policies, and ciphers and protocols that are secure. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about setting up TLS/SSL for ELBv1 refer to the Listeners for your Classic Load Balancer section of the Elastic Load Balancing Classic Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-listener-config.html#elb-listener-protocols"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                            "Resources": [
                                {
                                    "Type": "AwsTrustedAdvisorCheck",
                                    "Id": checkId,
                                    "Partition": awsPartition,
                                    "Region": awsRegion
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
                            "Id": awsAccountId + checkId + "/trusted-advisor-failing-elb-listener-security-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": awsAccountId + checkId,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[TrustedAdvisor.2] Trusted Advisor check results for ELB Listener Security should be investigated",
                            "Description": "Trusted Advisor Check for ELB Listener Security with a Check Id of "
                            + checkId
                            + ". is passing.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about setting up TLS/SSL for ELBv1 refer to the Listeners for your Classic Load Balancer section of the Elastic Load Balancing Classic Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-listener-config.html#elb-listener-protocols"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                            "Resources": [
                                {
                                    "Type": "AwsTrustedAdvisorCheck",
                                    "Id": checkId,
                                    "Partition": awsPartition,
                                    "Region": awsRegion
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
                                    "ISO 27001:2013 A.14.1.3"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    break
                else:
                    continue
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('You are not subscribed to AWS Premium Support - cannot use the Trusted Advisor Auditor')
            else:
                print(error)
    else:
        print('AWS Health Global endpoint is located in us-east-1')

@registry.register_check("support")
def trusted_advisor_failing_cloudfront_ssl_cert_iam_certificate_store_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[TrustedAdvisor.3] Trusted Advisor check results for CloudFront Custom SSL Certificates in the IAM Certificate Store should be investigated"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if awsRegion == 'us-east-1':
        try:
            for t in describe_trusted_advisor_checks(cache=cache)["checks"]:
                if str(t["name"]) == "CloudFront Custom SSL Certificates in the IAM Certificate Store":
                    checkId = str(t["id"])
                    # this is a failing check
                    if int(support.describe_trusted_advisor_check_result(checkId=checkId)["result"]["resourcesSummary"]["resourcesFlagged"]) >= 1:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": awsAccountId + checkId + "/trusted-advisor-failing-cloudfront-ssl-cert-iam-cert-store-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": awsAccountId + checkId,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[TrustedAdvisor.3] Trusted Advisor check results for CloudFront Custom SSL Certificates in the IAM Certificate Store should be investigated",
                            "Description": "Trusted Advisor Check for CloudFront Custom SSL Certificates in the IAM Certificate Store with a Check Id of "
                            + checkId
                            + ". has failed. Trusted Advisor checks the SSL certificates for CloudFront alternate domain names in the IAM certificate store and alerts you if the certificate is expired, will soon expire, uses outdated encryption, or is not configured correctly for the distribution. When a custom certificate for an alternate domain name expires, browsers that display your CloudFront content might show a warning message about the security of your website. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about setting up HTTPS for CloudFront refer to the Using HTTPS with CloudFront section of the Amazon CloudFront Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                            "Resources": [
                                {
                                    "Type": "AwsTrustedAdvisorCheck",
                                    "Id": checkId,
                                    "Partition": awsPartition,
                                    "Region": awsRegion
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
                            "Id": awsAccountId + checkId + "/trusted-advisor-failing-cloudfront-ssl-cert-iam-cert-store-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": awsAccountId + checkId,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[TrustedAdvisor.3] Trusted Advisor check results for CloudFront Custom SSL Certificates in the IAM Certificate Store should be investigated",
                            "Description": "Trusted Advisor Check for CloudFront Custom SSL Certificates in the IAM Certificate Store with a Check Id of "
                            + checkId
                            + ". is passing.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about setting up HTTPS for CloudFront refer to the Using HTTPS with CloudFront section of the Amazon CloudFront Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                            "Resources": [
                                {
                                    "Type": "AwsTrustedAdvisorCheck",
                                    "Id": checkId,
                                    "Partition": awsPartition,
                                    "Region": awsRegion
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
                                    "ISO 27001:2013 A.14.1.3"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    break
                else:
                    continue
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('You are not subscribed to AWS Premium Support - cannot use the Trusted Advisor Auditor')
            else:
                print(error)
    else:
        print('AWS Health Global endpoint is located in us-east-1')

@registry.register_check("support")
def trusted_advisor_failing_cloudfront_ssl_cert_on_origin_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[TrustedAdvisor.4] Trusted Advisor check results for CloudFront SSL Certificate on the Origin Server should be investigated"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if awsRegion == 'us-east-1':
        try:
            for t in describe_trusted_advisor_checks(cache=cache)["checks"]:
                if str(t["name"]) == "CloudFront SSL Certificate on the Origin Server":
                    checkId = str(t["id"])
                    # this is a failing check
                    if int(support.describe_trusted_advisor_check_result(checkId=checkId)["result"]["resourcesSummary"]["resourcesFlagged"]) >= 1:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": awsAccountId + checkId + "/trusted-advisor-failing-cloudfront-ssl-origin-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": awsAccountId + checkId,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[TrustedAdvisor.4] Trusted Advisor check results for CloudFront SSL Certificate on the Origin Server should be investigated",
                            "Description": "Trusted Advisor Check for CloudFront SSL Certificate on the Origin Server with a Check Id of "
                            + checkId
                            + ". has failed. Trusted Advisor checks your origin server for SSL certificates that are expired, about to expire, missing, or that use outdated encryption. If a certificate is expired, CloudFront responds to requests for your content with HTTP status code 502, Bad Gateway. Certificates that were encrypted by using the SHA-1 hashing algorithm are being deprecated by web browsers such as Chrome and Firefox. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about setting up HTTPS for CloudFront refer to the Using HTTPS with CloudFront section of the Amazon CloudFront Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                            "Resources": [
                                {
                                    "Type": "AwsTrustedAdvisorCheck",
                                    "Id": checkId,
                                    "Partition": awsPartition,
                                    "Region": awsRegion
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
                            "Id": awsAccountId + checkId + "/trusted-advisor-failing-cloudfront-ssl-origin-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": awsAccountId + checkId,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[TrustedAdvisor.4] Trusted Advisor check results for CloudFront SSL Certificate on the Origin Server should be investigated",
                            "Description": "Trusted Advisor Check for CloudFront SSL Certificate on the Origin Server with a Check Id of "
                            + checkId
                            + ". is passing.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about setting up HTTPS for CloudFront refer to the Using HTTPS with CloudFront section of the Amazon CloudFront Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                            "Resources": [
                                {
                                    "Type": "AwsTrustedAdvisorCheck",
                                    "Id": checkId,
                                    "Partition": awsPartition,
                                    "Region": awsRegion
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
                                    "ISO 27001:2013 A.14.1.3"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    break
                else:
                    continue
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('You are not subscribed to AWS Premium Support - cannot use the Trusted Advisor Auditor')
            else:
                print(error)
    else:
        print('AWS Health Global endpoint is located in us-east-1')

@registry.register_check("support")
def trusted_advisor_failing_exposed_access_keys_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[TrustedAdvisor.5] Trusted Advisor check results for Exposed Access Keys should be investigated"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if awsRegion == 'us-east-1':
        try:
            for t in describe_trusted_advisor_checks(cache=cache)["checks"]:
                if str(t["name"]) == "Exposed Access Keys":
                    checkId = str(t["id"])
                    # this is a failing check
                    if int(support.describe_trusted_advisor_check_result(checkId=checkId)["result"]["resourcesSummary"]["resourcesFlagged"]) >= 1:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": awsAccountId + checkId + "/trusted-advisor-expose-iam-keys-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": awsAccountId + checkId,
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
                            "Title": "[TrustedAdvisor.5] Trusted Advisor check results for Exposed Access Keys should be investigated",
                            "Description": "Trusted Advisor Check for Exposed Access Keys with a Check Id of "
                            + checkId
                            + ". has failed. Trusted Advisor checks popular code repositories for access keys that have been exposed to the public and for irregular Amazon Elastic Compute Cloud (Amazon EC2) usage that could be the result of a compromised access key. An access key consists of an access key ID and the corresponding secret access key. Exposed access keys pose a security risk to your account and other users. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about rotating access keys refer to the Managing access keys for IAM users section of the AWS Identity and Access Management User Guide.",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                            "Resources": [
                                {
                                    "Type": "AwsTrustedAdvisorCheck",
                                    "Id": checkId,
                                    "Partition": awsPartition,
                                    "Region": awsRegion
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
                            "Id": awsAccountId + checkId + "/trusted-advisor-expose-iam-keys-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": awsAccountId + checkId,
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
                            "Title": "[TrustedAdvisor.5] Trusted Advisor check results for Exposed Access Keys should be investigated",
                            "Description": "Trusted Advisor Check for Exposed Access Keys with a Check Id of "
                            + checkId
                            + ". has failed. Trusted Advisor checks popular code repositories for access keys that have been exposed to the public and for irregular Amazon Elastic Compute Cloud (Amazon EC2) usage that could be the result of a compromised access key. An access key consists of an access key ID and the corresponding secret access key. Exposed access keys pose a security risk to your account and other users. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about rotating access keys refer to the Managing access keys for IAM users section of the AWS Identity and Access Management User Guide.",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                            "Resources": [
                                {
                                    "Type": "AwsTrustedAdvisorCheck",
                                    "Id": checkId,
                                    "Partition": awsPartition,
                                    "Region": awsRegion
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
                                    "ISO 27001:2013 A.9.4.3"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    break
                else:
                    continue
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('You are not subscribed to AWS Premium Support - cannot use the Trusted Advisor Auditor')
            else:
                print(error)
    else:
        print('AWS Health Global endpoint is located in us-east-1')