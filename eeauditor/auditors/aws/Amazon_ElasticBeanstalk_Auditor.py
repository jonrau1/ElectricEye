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

registry = CheckRegister()

# loop through EBS volumes
def describe_environments(cache, session):
    elasticbeanstalk = session.client("elasticbeanstalk")
    response = cache.get("describe_environments")
    if response:
        return response
    cache["describe_environments"] = elasticbeanstalk.describe_environments()
    return cache["describe_environments"]

@registry.register_check("elasticbeanstalk")
def elasticbeanstalk_imdsv1_disabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ElasticBeanstalk.1] Elastic Beanstalk environments should disable IMDSv1"""
    elasticbeanstalk = session.client("elasticbeanstalk")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for envs in describe_environments(cache, session)["Environments"]:
        envArn = envs["EnvironmentArn"]
        envName = envs["EnvironmentName"]
        appName = envs["ApplicationName"]
        # loop through all of the configs and option sets to find what we want
        for configs in elasticbeanstalk.describe_configuration_settings(
            ApplicationName=appName,
            EnvironmentName=envName
        )["ConfigurationSettings"]:
            for opts in configs["OptionSettings"]:
                if opts["OptionName"] == "DisableIMDSv1":
                    # this is a failing check
                    if opts["Value"] == "false":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{envArn}/beanstalk-env-imdsv1-disabled-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": envArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[ElasticBeanstalk.1] Elastic Beanstalk environments should disable IMDSv1",
                            "Description": f"Elastic Beanstalk environment {envName} does not disable Instance Metadata Service Version 1 (IMDSv1). IMDSv2 uses session-oriented requests and mitigates several types of vulnerabilities that could be used to try to access the IMDS. For information about these two methods, see Configuring the instance metadata service in the Amazon EC2 User Guide for Linux Instances. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If you Elastic Beanstalk environment should be configured to use IMDSv2 only refer to the Configuring the instance metadata service on your environment's instances section of the AWS Elastic Beanstalk Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environments-cfg-ec2-imds.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElasticBeanstalkEnvironment",
                                    "Id": envArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElasticBeanstalkEnvironment": {
                                            "ApplicationName": appName,
                                            "EnvironmentArn": envArn,
                                            "EnvironmentId": envs["EnvironmentId"],
                                            "EnvironmentName": envName,
                                            "PlatformArn": envs["PlatformArn"],
                                            "Status": envs["Status"],
                                            "VersionLabel": envs["VersionLabel"],
                                            "Tier": {
                                                "Name": envs["Tier"]["Name"],
                                                "Type": envs["Tier"]["Type"],
                                                "Version": envs["Tier"]["Version"]
                                            }
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.AC-4",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-2",
                                    "NIST SP 800-53 Rev. 4 AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-5",
                                    "NIST SP 800-53 Rev. 4 AC-6",
                                    "NIST SP 800-53 Rev. 4 AC-14",
                                    "NIST SP 800-53 Rev. 4 AC-16",
                                    "NIST SP 800-53 Rev. 4 AC-24",
                                    "AICPA TSC CC6.3",
                                    "ISO 27001:2013 A.6.1.2",
                                    "ISO 27001:2013 A.9.1.2",
                                    "ISO 27001:2013 A.9.2.3",
                                    "ISO 27001:2013 A.9.4.1",
                                    "ISO 27001:2013 A.9.4.4",
                                    "ISO 27001:2013 A.9.4.5"
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
                            "Id": f"{envArn}/beanstalk-env-imdsv1-disabled-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": envArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ElasticBeanstalk.1] Elastic Beanstalk environments should disable IMDSv1",
                            "Description": f"Elastic Beanstalk environment {envName} disables Instance Metadata Service Version 1 (IMDSv1).",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If you Elastic Beanstalk environment should be configured to use IMDSv2 only refer to the Configuring the instance metadata service on your environment's instances section of the AWS Elastic Beanstalk Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environments-cfg-ec2-imds.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElasticBeanstalkEnvironment",
                                    "Id": envArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElasticBeanstalkEnvironment": {
                                            "ApplicationName": appName,
                                            "EnvironmentArn": envArn,
                                            "EnvironmentId": envs["EnvironmentId"],
                                            "EnvironmentName": envName,
                                            "PlatformArn": envs["PlatformArn"],
                                            "Status": envs["Status"],
                                            "VersionLabel": envs["VersionLabel"],
                                            "Tier": {
                                                "Name": envs["Tier"]["Name"],
                                                "Type": envs["Tier"]["Type"],
                                                "Version": envs["Tier"]["Version"]
                                            }
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.AC-4",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-2",
                                    "NIST SP 800-53 Rev. 4 AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-5",
                                    "NIST SP 800-53 Rev. 4 AC-6",
                                    "NIST SP 800-53 Rev. 4 AC-14",
                                    "NIST SP 800-53 Rev. 4 AC-16",
                                    "NIST SP 800-53 Rev. 4 AC-24",
                                    "AICPA TSC CC6.3",
                                    "ISO 27001:2013 A.6.1.2",
                                    "ISO 27001:2013 A.9.1.2",
                                    "ISO 27001:2013 A.9.2.3",
                                    "ISO 27001:2013 A.9.4.1",
                                    "ISO 27001:2013 A.9.4.4",
                                    "ISO 27001:2013 A.9.4.5"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    # stop the loop after the right option is found
                    break
                else:
                    continue

@registry.register_check("elasticbeanstalk")
def elasticbeanstalk_platform_auto_update_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ElasticBeanstalk.2] Elastic Beanstalk environments should be configured to automatically apply updates and refresh instances"""
    elasticbeanstalk = session.client("elasticbeanstalk")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for envs in describe_environments(cache, session)["Environments"]:
        envArn = envs["EnvironmentArn"]
        envName = envs["EnvironmentName"]
        appName = envs["ApplicationName"]
        # loop through all of the configs and option sets to find what we want
        for configs in elasticbeanstalk.describe_configuration_settings(
            ApplicationName=appName,
            EnvironmentName=envName
        )["ConfigurationSettings"]:
            for opts in configs["OptionSettings"]:
                if opts["OptionName"] == "InstanceRefreshEnabled":
                    # this is a failing check
                    if opts["Value"] == "false":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{envArn}/beanstalk-env-auto-update-refresh-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": envArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[ElasticBeanstalk.2] Elastic Beanstalk environments should be configured to automatically apply updates and refresh instances",
                            "Description": f"Elastic Beanstalk environment {envName} is not configured to automatically update and refresh instances. Elastic Beanstalk regularly releases platform updates to provide fixes, software updates, and new features. With managed platform updates, you can configure your environment to automatically upgrade to the latest version of a platform during a scheduled maintenance window. Your application remains in service during the update process with no reduction in capacity. Managed updates are available on both single-instance and load-balanced environments. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If you Elastic Beanstalk environment should be configured to use IMDSv2 only refer to the Configuring the instance metadata service on your environment's instances section of the AWS Elastic Beanstalk Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environments-cfg-ec2-imds.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElasticBeanstalkEnvironment",
                                    "Id": envArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElasticBeanstalkEnvironment": {
                                            "ApplicationName": appName,
                                            "EnvironmentArn": envArn,
                                            "EnvironmentId": envs["EnvironmentId"],
                                            "EnvironmentName": envName,
                                            "PlatformArn": envs["PlatformArn"],
                                            "Status": envs["Status"],
                                            "VersionLabel": envs["VersionLabel"],
                                            "Tier": {
                                                "Name": envs["Tier"]["Name"],
                                                "Type": envs["Tier"]["Type"],
                                                "Version": envs["Tier"]["Version"]
                                            }
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 ID.AM-2",
                                    "NIST SP 800-53 Rev. 4 CM-8",
                                    "NIST SP 800-53 Rev. 4 PM-5",
                                    "AICPA TSC CC3.2",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.1.1",
                                    "ISO 27001:2013 A.8.1.2",
                                    "ISO 27001:2013 A.12.5.1"
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
                            "Id": f"{envArn}/beanstalk-env-auto-update-refresh-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": envArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ElasticBeanstalk.2] Elastic Beanstalk environments should be configured to automatically apply updates and refresh instances",
                            "Description": f"Elastic Beanstalk environment {envName} is configured to automatically update and refresh instances.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If you Elastic Beanstalk environment should be configured to use IMDSv2 only refer to the Configuring the instance metadata service on your environment's instances section of the AWS Elastic Beanstalk Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environments-cfg-ec2-imds.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElasticBeanstalkEnvironment",
                                    "Id": envArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElasticBeanstalkEnvironment": {
                                            "ApplicationName": appName,
                                            "EnvironmentArn": envArn,
                                            "EnvironmentId": envs["EnvironmentId"],
                                            "EnvironmentName": envName,
                                            "PlatformArn": envs["PlatformArn"],
                                            "Status": envs["Status"],
                                            "VersionLabel": envs["VersionLabel"],
                                            "Tier": {
                                                "Name": envs["Tier"]["Name"],
                                                "Type": envs["Tier"]["Type"],
                                                "Version": envs["Tier"]["Version"]
                                            }
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 ID.AM-2",
                                    "NIST SP 800-53 Rev. 4 CM-8",
                                    "NIST SP 800-53 Rev. 4 PM-5",
                                    "AICPA TSC CC3.2",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.1.1",
                                    "ISO 27001:2013 A.8.1.2",
                                    "ISO 27001:2013 A.12.5.1"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    # stop the loop after the right option is found
                    break
                else:
                    continue

@registry.register_check("elasticbeanstalk")
def elasticbeanstalk_enhanced_health_reporting_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ElasticBeanstalk.3] Elastic Beanstalk environments should have enhanced health reporting enabled"""
    elasticbeanstalk = session.client("elasticbeanstalk")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for envs in describe_environments(cache, session)["Environments"]:
        envArn = envs["EnvironmentArn"]
        envName = envs["EnvironmentName"]
        appName = envs["ApplicationName"]
        # loop through all of the configs and option sets to find what we want
        for configs in elasticbeanstalk.describe_configuration_settings(
            ApplicationName=appName,
            EnvironmentName=envName
        )["ConfigurationSettings"]:
            for opts in configs["OptionSettings"]:
                if opts["OptionName"] == "EnhancedHealthAuthEnabled":
                    # this is a failing check
                    if opts["Value"] == "false":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{envArn}/beanstalk-env-enhanced-health-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": envArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[ElasticBeanstalk.3] Elastic Beanstalk environments should have enhanced health reporting enabled",
                            "Description": f"Elastic Beanstalk environment {envName} does not have enhanced health reporting enabled. Elastic Beanstalk enhanced health reporting enables a more rapid response to changes in the health of the underlying infrastructure. These changes could result in a lack of availability of the application. Elastic Beanstalk enhanced health reporting provides a status descriptor to gauge the severity of the identified issues and identify possible causes to investigate. The Elastic Beanstalk health agent, included in supported Amazon Machine Images (AMIs), evaluates logs and metrics of environment EC2 instances. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If you Elastic Beanstalk environment should be configured to use enhanced health reporting refer to the Enhanced health reporting and monitoring section of the AWS Elastic Beanstalk Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/health-enhanced.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElasticBeanstalkEnvironment",
                                    "Id": envArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElasticBeanstalkEnvironment": {
                                            "ApplicationName": appName,
                                            "EnvironmentArn": envArn,
                                            "EnvironmentId": envs["EnvironmentId"],
                                            "EnvironmentName": envName,
                                            "PlatformArn": envs["PlatformArn"],
                                            "Status": envs["Status"],
                                            "VersionLabel": envs["VersionLabel"],
                                            "Tier": {
                                                "Name": envs["Tier"]["Name"],
                                                "Type": envs["Tier"]["Type"],
                                                "Version": envs["Tier"]["Version"]
                                            }
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-3",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 IR-5",
                                    "NIST SP 800-53 Rev. 4 IR-8",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.12.4.1",
                                    "ISO 27001:2013 A.16.1.7"
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
                            "Id": f"{envArn}/beanstalk-env-enhanced-health-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": envArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ElasticBeanstalk.3] Elastic Beanstalk environments should have enhanced health reporting enabled",
                            "Description": f"Elastic Beanstalk environment {envName} has enhanced health reporting enabled.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If you Elastic Beanstalk environment should be configured to use enhanced health reporting refer to the Enhanced health reporting and monitoring section of the AWS Elastic Beanstalk Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/health-enhanced.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElasticBeanstalkEnvironment",
                                    "Id": envArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElasticBeanstalkEnvironment": {
                                            "ApplicationName": appName,
                                            "EnvironmentArn": envArn,
                                            "EnvironmentId": envs["EnvironmentId"],
                                            "EnvironmentName": envName,
                                            "PlatformArn": envs["PlatformArn"],
                                            "Status": envs["Status"],
                                            "VersionLabel": envs["VersionLabel"],
                                            "Tier": {
                                                "Name": envs["Tier"]["Name"],
                                                "Type": envs["Tier"]["Type"],
                                                "Version": envs["Tier"]["Version"]
                                            }
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-3",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 IR-5",
                                    "NIST SP 800-53 Rev. 4 IR-8",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.12.4.1",
                                    "ISO 27001:2013 A.16.1.7"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    # stop the loop after the right option is found
                    break
                else:
                    continue

@registry.register_check("elasticbeanstalk")
def elasticbeanstalk_log_streaming_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ElasticBeanstalk.4] Elastic Beanstalk environments should have log streaming enabled"""
    elasticbeanstalk = session.client("elasticbeanstalk")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for envs in describe_environments(cache, session)["Environments"]:
        envArn = envs["EnvironmentArn"]
        envName = envs["EnvironmentName"]
        appName = envs["ApplicationName"]
        # loop through all of the configs and option sets to find what we want
        for configs in elasticbeanstalk.describe_configuration_settings(
            ApplicationName=appName,
            EnvironmentName=envName
        )["ConfigurationSettings"]:
            for opts in configs["OptionSettings"]:
                if opts["OptionName"] == "StreamLogs":
                    # this is a failing check
                    if opts["Value"] == "false":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{envArn}/beanstalk-env-log-streaming-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": envArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[ElasticBeanstalk.4] Elastic Beanstalk environments should have log streaming enabled",
                            "Description": f"Elastic Beanstalk environment {envName} does not have log streaming enabled. Elastic Beanstalk installs a CloudWatch log agent with the default configuration settings on each instance it creates. Learn more in the CloudWatch Logs Agent Reference. When you enable instance log streaming to CloudWatch Logs, Elastic Beanstalk sends log files from your environment's instances to CloudWatch Logs. Different platforms stream different logs. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If you Elastic Beanstalk environment should be configured to use log streaming refer to the Using Elastic Beanstalk with Amazon CloudWatch Logs section of the AWS Elastic Beanstalk Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/AWSHowTo.cloudwatchlogs.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElasticBeanstalkEnvironment",
                                    "Id": envArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElasticBeanstalkEnvironment": {
                                            "ApplicationName": appName,
                                            "EnvironmentArn": envArn,
                                            "EnvironmentId": envs["EnvironmentId"],
                                            "EnvironmentName": envName,
                                            "PlatformArn": envs["PlatformArn"],
                                            "Status": envs["Status"],
                                            "VersionLabel": envs["VersionLabel"],
                                            "Tier": {
                                                "Name": envs["Tier"]["Name"],
                                                "Type": envs["Tier"]["Type"],
                                                "Version": envs["Tier"]["Version"]
                                            }
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-3",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 IR-5",
                                    "NIST SP 800-53 Rev. 4 IR-8",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.12.4.1",
                                    "ISO 27001:2013 A.16.1.7"
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
                            "Id": f"{envArn}/beanstalk-env-log-streaming-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": envArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ElasticBeanstalk.4] Elastic Beanstalk environments should have log streaming enabled",
                            "Description": f"Elastic Beanstalk environment {envName} has log streaming enabled.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If you Elastic Beanstalk environment should be configured to use log streaming refer to the Using Elastic Beanstalk with Amazon CloudWatch Logs section of the AWS Elastic Beanstalk Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/AWSHowTo.cloudwatchlogs.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElasticBeanstalkEnvironment",
                                    "Id": envArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElasticBeanstalkEnvironment": {
                                            "ApplicationName": appName,
                                            "EnvironmentArn": envArn,
                                            "EnvironmentId": envs["EnvironmentId"],
                                            "EnvironmentName": envName,
                                            "PlatformArn": envs["PlatformArn"],
                                            "Status": envs["Status"],
                                            "VersionLabel": envs["VersionLabel"],
                                            "Tier": {
                                                "Name": envs["Tier"]["Name"],
                                                "Type": envs["Tier"]["Type"],
                                                "Version": envs["Tier"]["Version"]
                                            }
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-3",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 IR-5",
                                    "NIST SP 800-53 Rev. 4 IR-8",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.12.4.1",
                                    "ISO 27001:2013 A.16.1.7"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    # stop the loop after the right option is found
                    break
                else:
                    continue

@registry.register_check("elasticbeanstalk")
def elasticbeanstalk_xray_tracing_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ElasticBeanstalk.5] Elastic Beanstalk environments should have tracing enabled"""
    elasticbeanstalk = session.client("elasticbeanstalk")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for envs in describe_environments(cache, session)["Environments"]:
        envArn = envs["EnvironmentArn"]
        envName = envs["EnvironmentName"]
        appName = envs["ApplicationName"]
        # loop through all of the configs and option sets to find what we want
        for configs in elasticbeanstalk.describe_configuration_settings(
            ApplicationName=appName,
            EnvironmentName=envName
        )["ConfigurationSettings"]:
            for opts in configs["OptionSettings"]:
                if opts["OptionName"] == "XRayEnabled":
                    # this is a failing check
                    if opts["Value"] == "false":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{envArn}/beanstalk-env-xray-tracing-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": envArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[ElasticBeanstalk.5] Elastic Beanstalk environments should have tracing enabled",
                            "Description": f"Elastic Beanstalk environment {envName} does not have tracing enabled. To relay trace data from your application to AWS X-Ray, you can run the X-Ray daemon on your Elastic Beanstalk environment's Amazon EC2 instances. Elastic Beanstalk platforms provide a configuration option that you can set to run the daemon automatically. You can enable the daemon in a configuration file in your source code or by choosing an option in the Elastic Beanstalk console. When you enable the configuration option, the daemon is installed on the instance and runs as a service. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If you Elastic Beanstalk environment should be configured to use AWS X-Ray tracing refer to the Running the X-Ray daemon on AWS Elastic Beanstalk section of the AWS X-Ray Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/xray/latest/devguide/xray-daemon-beanstalk.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElasticBeanstalkEnvironment",
                                    "Id": envArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElasticBeanstalkEnvironment": {
                                            "ApplicationName": appName,
                                            "EnvironmentArn": envArn,
                                            "EnvironmentId": envs["EnvironmentId"],
                                            "EnvironmentName": envName,
                                            "PlatformArn": envs["PlatformArn"],
                                            "Status": envs["Status"],
                                            "VersionLabel": envs["VersionLabel"],
                                            "Tier": {
                                                "Name": envs["Tier"]["Name"],
                                                "Type": envs["Tier"]["Type"],
                                                "Version": envs["Tier"]["Version"]
                                            }
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-3",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 IR-5",
                                    "NIST SP 800-53 Rev. 4 IR-8",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.12.4.1",
                                    "ISO 27001:2013 A.16.1.7"
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
                            "Id": f"{envArn}/beanstalk-env-xray-tracing-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": envArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ElasticBeanstalk.5] Elastic Beanstalk environments should have tracing enabled",
                            "Description": f"Elastic Beanstalk environment {envName} has tracing enabled.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If you Elastic Beanstalk environment should be configured to use AWS X-Ray tracing refer to the Running the X-Ray daemon on AWS Elastic Beanstalk section of the AWS X-Ray Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/xray/latest/devguide/xray-daemon-beanstalk.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElasticBeanstalkEnvironment",
                                    "Id": envArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElasticBeanstalkEnvironment": {
                                            "ApplicationName": appName,
                                            "EnvironmentArn": envArn,
                                            "EnvironmentId": envs["EnvironmentId"],
                                            "EnvironmentName": envName,
                                            "PlatformArn": envs["PlatformArn"],
                                            "Status": envs["Status"],
                                            "VersionLabel": envs["VersionLabel"],
                                            "Tier": {
                                                "Name": envs["Tier"]["Name"],
                                                "Type": envs["Tier"]["Type"],
                                                "Version": envs["Tier"]["Version"]
                                            }
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-3",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 IR-5",
                                    "NIST SP 800-53 Rev. 4 IR-8",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.12.4.1",
                                    "ISO 27001:2013 A.16.1.7"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    # stop the loop after the right option is found
                    break
                else:
                    continue