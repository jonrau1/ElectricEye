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