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

import boto3
import datetime
import json
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
ec2 = boto3.client("ec2")
elasticbeanstalk = boto3.client("elasticbeanstalk")

# loop through EBS volumes
def describe_environments(cache):
    response = cache.get("describe_environments")
    if response:
        return response
    cache["describe_environments"] = elasticbeanstalk.describe_environments()
    return cache["describe_environments"]

@registry.register_check("elasticbeanstalk")
def elasticbeanstalk_imdsv1_disabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ElasticBeanstalk.1] Elastic Beanstalk environments should disable IMDSv1"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for envs in describe_environments(cache)["Environments"]:
        envArn = envs["EnvironmentArn"]
        envName = envs["EnvironmentName"]
        appName = envs["ApplicationName"]
        # loop through all of the configs and option sets to find what we want
        for configs in elasticbeanstalk.describe_configuration_settings(
            ApplicationName=appName,
            EnvironmentName=envName
        )["ConfigurationSettings"]:
            # TODO : DELETE THIS
            optionSets = configs["OptionSettings"]
            with open('~/ebconfigs.json', 'w') as jsonfile:
                json.dump(optionSets, jsonfile, indent=4, default=str)
            # TODO : DELETE THE ABOVE
            for opts in configs["OptionSettings"]:
                print(opts["OptionName"])
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
                            "Description": f"Elastic Beanstalk environment {envName} does not disable Instance Metadata Service Version 1 (IMDSv1).  IMDSv2 uses session-oriented requests and mitigates several types of vulnerabilities that could be used to try to access the IMDS. For information about these two methods, see Configuring the instance metadata service in the Amazon EC2 User Guide for Linux Instances. Refer to the remediation instructions if this configuration is not intended.",
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
                                            "Cname": envs["CNAME"],
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
                                    "NIST CSF PR.AC-4",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-2",
                                    "NIST SP 800-53 AC-3",
                                    "NIST SP 800-53 AC-5",
                                    "NIST SP 800-53 AC-6",
                                    "NIST SP 800-53 AC-14",
                                    "NIST SP 800-53 AC-16",
                                    "NIST SP 800-53 AC-24",
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
                            "Description": f"Elastic Beanstalk environment {envName} does not disable Instance Metadata Service Version 1 (IMDSv1).  IMDSv2 uses session-oriented requests and mitigates several types of vulnerabilities that could be used to try to access the IMDS. For information about these two methods, see Configuring the instance metadata service in the Amazon EC2 User Guide for Linux Instances. Refer to the remediation instructions if this configuration is not intended.",
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
                                            "Cname": envs["CNAME"],
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
                                    "NIST CSF PR.AC-4",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-2",
                                    "NIST SP 800-53 AC-3",
                                    "NIST SP 800-53 AC-5",
                                    "NIST SP 800-53 AC-6",
                                    "NIST SP 800-53 AC-14",
                                    "NIST SP 800-53 AC-16",
                                    "NIST SP 800-53 AC-24",
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

#