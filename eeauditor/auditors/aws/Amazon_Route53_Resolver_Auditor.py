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
from check_register import CheckRegister

registry = CheckRegister()

# create boto3 clients
ec2 = boto3.client("ec2")
route53resolver = boto3.client("route53resolver")

# loop through vpcs
def describe_vpcs(cache):
    response = cache.get("describe_vpcs")
    if response:
        return response
    cache["describe_vpcs"] = ec2.describe_vpcs(DryRun=False)
    return cache["describe_vpcs"]

@registry.register_check("route53resolver")
def vpc_default_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Route53Resolver.1] VPCs should have Route 53 Resolver DNS Query Logging Configured"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Loop the VPCs in Cache
    for vpcs in describe_vpcs(cache=cache)["Vpcs"]:
        vpcId = str(vpcs["VpcId"])
        vpcArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}vpc/{vpcId}"
        # Check for Query Log Configs filtered by VPC ID. 
        # If any empty list is returned there is not query logging configured
        r = route53resolver.list_resolver_query_log_configs(
            Filters=[
                {
                    'Name': 'HostVPCId',
                    'Values': [vpcId]
                }
            ]
        )
        print(r)

        '''
        defaultVpcCheck = str(vpcs["IsDefault"])
        
        if defaultVpcCheck == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/vpc-is-default-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC.1] Consider deleting the Default VPC if unused",
                "Description": "VPC "
                + vpcId
                + " has been identified as the Default VPC, consider deleting this VPC if it is not necessary for daily operations. The Default VPC in AWS Regions not typically used can serve as a persistence area for malicious actors, additionally, many services will automatically use this VPC which can lead to a degraded security posture. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the default VPC refer to the Deleting Your Default Subnets and Default VPC section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html#deleting-default-vpc",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"VpcId": vpcId}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
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
                "Id": vpcArn + "/vpc-is-default-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.1] Consider deleting the Default VPC if unused",
                "Description": "VPC " + vpcId + " is not the Default VPC",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the default VPC refer to the Deleting Your Default Subnets and Default VPC section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html#deleting-default-vpc",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"VpcId": vpcId}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        '''