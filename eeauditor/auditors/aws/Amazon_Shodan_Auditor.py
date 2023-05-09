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
import os
import requests
import socket
import datetime
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

class ShodanError(Exception):
    pass

try:
    ssm = boto3.client("ssm")
    apiKeyParam = os.environ["SHODAN_API_KEY_PARAM"]
    if apiKeyParam == ("placeholder" or "" or None):
        raise ShodanError("No valid Shodan API Key")
    else:
        shodanApiKey = ssm.get_parameter(Name=apiKeyParam, WithDecryption=True)["Parameter"]["Value"]
except KeyError:
    os.environ["SHODAN_API_KEY_PARAM"] = None

# Shodan information for Requests
shodanUrl = "https://api.shodan.io/shodan/host/"

@registry.register_check("aws.shodan")
def public_ec2_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.EC2.1] EC2 instances with public IP addresses should be monitored for being indexed by Shodan"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    response = ec2.describe_instances(DryRun=False, MaxResults=500)
    for res in response["Reservations"]:
        for inst in res["Instances"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(inst,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            ec2Type = str(inst["InstanceType"])
            ec2AmiId = str(inst["ImageId"])
            ec2Id = str(inst["InstanceId"])
            ec2Arn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}instance/{ec2Id}"
            ec2PrivateIp = str(inst["PrivateIpAddress"])
            ec2VpcId = str(inst["VpcId"])
            ec2SubnetId = str(inst["SubnetId"])
            ec2PublicIp = str(inst["PublicIpAddress"])
            # use requests Library to check the Shodan index for your host
            r = requests.get(url=shodanUrl + ec2PublicIp + "?key=" + shodanApiKey)
            data = r.json()
            shodanOutput = str(data)
            if shodanOutput == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": ec2Arn + "/" + ec2PublicIp + "/ec2-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": ec2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.EC2.1] EC2 instances with public IP addresses should be monitored for being indexed by Shodan",
                    "Description": "EC2 instance "
                    + ec2Id
                    + " has not been indexed by Shodan.",
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Compute",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": ec2Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": ec2Type,
                                    "ImageId": ec2AmiId,
                                    "IpV4Addresses": [ec2PublicIp, ec2PrivateIp,],
                                    "VpcId": ec2VpcId,
                                    "SubnetId": ec2SubnetId,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": ec2Arn + "/" + ec2PublicIp + "/ec2-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": ec2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.EC2.1] EC2 instances with public IP addresses should be monitored for being indexed by Shodan",
                    "Description": "EC2 instance "
                    + ec2Id
                    + " has been indexed by Shodan on IP address "
                    + ec2PublicIp
                    + ". review the Shodan.io host information in the SourceUrl or ThreatIntelIndicators.SourceUrl fields for information about what ports and services are exposed and then take action to reduce exposure and harden your host.",
                    "SourceUrl": "https://www.shodan.io/host/" + ec2PublicIp,
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Compute",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Instance"
                    },
                    "ThreatIntelIndicators": [
                        {
                            "Type": "IPV4_ADDRESS",
                            "Category": "EXPLOIT_SITE",
                            "Value": ec2PublicIp,
                            "LastObservedAt": iso8601time,
                            "Source": "Shodan.io",
                            "SourceUrl": "https://www.shodan.io/host/" + ec2PublicIp,
                        },
                    ],
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": ec2Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": ec2Type,
                                    "ImageId": ec2AmiId,
                                    "IpV4Addresses": [ec2PublicIp, ec2PrivateIp,],
                                    "VpcId": ec2VpcId,
                                    "SubnetId": ec2SubnetId,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding

@registry.register_check("aws.shodan")
def public_alb_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.ELBv2.1] Internet-facing Application Load Balancers should be monitored for being indexed by Shodan"""
    elbv2 = session.client("elbv2")
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    response = elbv2.describe_load_balancers()
    for lbs in response["LoadBalancers"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lbs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Scheme = str(lbs["Scheme"])
        elbv2Type = str(lbs["Type"])
        elbv2Name = str(lbs["LoadBalancerName"])
        elbv2Arn = str(lbs["LoadBalancerArn"])
        elbv2Vpc = str(lbs["VpcId"])
        elbv2Dns = str(lbs["DNSName"])
        if elbv2Scheme == "internet-facing" and elbv2Type == "application":
            # use Socket to do a DNS lookup and retrieve the IP address
            elbv2Ip = socket.gethostbyname(elbv2Dns)
            # use requests Library to check the Shodan index for your host
            r = requests.get(url=shodanUrl + elbv2Ip + "?key=" + shodanApiKey)
            data = r.json()
            shodanOutput = str(data)
            if shodanOutput == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": elbv2Arn + "/" + elbv2Dns + "/alb-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": elbv2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.ELBv2.1] Internet-facing Application Load Balancers should be monitored for being indexed by Shodan",
                    "Description": "ALB " + elbv2Name + " has not been indexed by Shodan.",
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "AWS Elastic Load Balancer V2",
                        "AssetComponent": "Application Load Balancer"
                    },
                    "Resources": [
                        {
                            "Type": "AwsElbv2LoadBalancer",
                            "Id": elbv2Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsElbv2LoadBalancer": {
                                    "DNSName": elbv2Dns,
                                    "Scheme": elbv2Scheme,
                                    "Type": elbv2Type,
                                    "VpcId": elbv2Vpc,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": elbv2Arn + "/" + elbv2Dns + "/alb-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": elbv2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.ELBv2.1] Internet-facing Application Load Balancers should be monitored for being indexed by Shodan",
                    "Description": "ALB "
                    + elbv2Name
                    + " has been indexed by Shodan on IP address "
                    + elbv2Ip
                    + " from DNS name "
                    + elbv2Dns
                    + ". review the Shodan.io host information in the SourceUrl or ThreatIntelIndicators.SourceUrl fields for information about what ports and services are exposed and then take action to reduce exposure and harden your load balancer.",
                    "SourceUrl": "https://www.shodan.io/host/" + elbv2Ip,
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "AWS Elastic Load Balancer V2",
                        "AssetComponent": "Application Load Balancer"
                    },
                    "ThreatIntelIndicators": [
                        {
                            "Type": "IPV4_ADDRESS",
                            "Category": "EXPLOIT_SITE",
                            "Value": elbv2Ip,
                            "LastObservedAt": iso8601time,
                            "Source": "Shodan.io",
                            "SourceUrl": "https://www.shodan.io/host/" + elbv2Ip,
                        },
                    ],
                    "Resources": [
                        {
                            "Type": "AwsElbv2LoadBalancer",
                            "Id": elbv2Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsElbv2LoadBalancer": {
                                    "DNSName": elbv2Dns,
                                    "Scheme": elbv2Scheme,
                                    "Type": elbv2Type,
                                    "VpcId": elbv2Vpc,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
        else:
            continue

@registry.register_check("aws.shodan")
def public_rds_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.RDS.1] Public accessible RDS instances should be monitored for being indexed by Shodan"""
    rds = session.client("rds")
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    response = rds.describe_db_instances()
    for rdsdb in response["DBInstances"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(rdsdb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rdsInstanceId = str(rdsdb["DBInstanceIdentifier"])
        rdsInstanceArn = str(rdsdb["DBInstanceArn"])
        rdsInstanceClass = str(rdsdb["DBInstanceClass"])
        rdsDbiRescId = str(rdsdb["DbiResourceId"])
        rdsEngine = str(rdsdb["Engine"])
        rdsEngineVersion = str(rdsdb["EngineVersion"])
        rdsDns = str(rdsdb["Endpoint"]["Address"])
        if rdsdb["PubliclyAccessible"] == True:
            # use Socket to do a DNS lookup and retrieve the IP address
            rdsIp = socket.gethostbyname(rdsDns)
            # use requests Library to check the Shodan index for your host
            r = requests.get(url=shodanUrl + rdsIp + "?key=" + shodanApiKey)
            data = r.json()
            shodanOutput = str(data)
            if shodanOutput == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": rdsInstanceArn + "/" + rdsDns + "/rds-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": rdsInstanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.RDS.1] Public accessible RDS instances should be monitored for being indexed by Shodan",
                    "Description": "RDS instance "
                    + rdsInstanceId
                    + " has not been indexed by Shodan.",
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Database",
                        "AssetService": "Amazon Relational Database Service",
                        "AssetComponent": "Database Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsRdsDbInstance",
                            "Id": rdsInstanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsRdsDbInstance": {
                                    "DBInstanceIdentifier": rdsInstanceId,
                                    "DBInstanceClass": rdsInstanceClass,
                                    "DbiResourceId": rdsDbiRescId,
                                    "Engine": rdsEngine,
                                    "EngineVersion": rdsEngineVersion,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": rdsInstanceArn + "/" + rdsDns + "/rds-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": rdsInstanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.RDS.1] Public accessible RDS instances should be monitored for being indexed by Shodan",
                    "Description": "RDS instance "
                    + rdsInstanceId
                    + " has been indexed by Shodan on IP address "
                    + rdsIp
                    + " from DNS name "
                    + rdsDns
                    + ". review the Shodan.io host information in the SourceUrl or ThreatIntelIndicators.SourceUrl fields for information about what ports and services are exposed and then take action to reduce exposure and harden your database.",
                    "SourceUrl": "https://www.shodan.io/host/" + rdsIp,
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Database",
                        "AssetService": "Amazon Relational Database Service",
                        "AssetComponent": "Database Instance"
                    },
                    "ThreatIntelIndicators": [
                        {
                            "Type": "IPV4_ADDRESS",
                            "Category": "EXPLOIT_SITE",
                            "Value": rdsIp,
                            "LastObservedAt": iso8601time,
                            "Source": "Shodan.io",
                            "SourceUrl": "https://www.shodan.io/host/" + rdsIp,
                        },
                    ],
                    "Resources": [
                        {
                            "Type": "AwsRdsDbInstance",
                            "Id": rdsInstanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsRdsDbInstance": {
                                    "DBInstanceIdentifier": rdsInstanceId,
                                    "DBInstanceClass": rdsInstanceClass,
                                    "DbiResourceId": rdsDbiRescId,
                                    "Engine": rdsEngine,
                                    "EngineVersion": rdsEngineVersion,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
        else:
            continue

@registry.register_check("aws.shodan")
def public_es_domain_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.Elasticsearch.1] OpenSearch/ElasticSearch Service domains outside of a VPC should be monitored for being indexed by Shodan"""
    elasticsearch = session.client("elasticsearch")
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    response = elasticsearch.list_domain_names()
    for domain in response["DomainNames"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(domain,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomain = str(domain["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomain)
        esDomainId = str(response["DomainStatus"]["DomainId"])
        esDomainName = str(response["DomainStatus"]["DomainName"])
        esDomainArn = str(response["DomainStatus"]["ARN"])
        esVersion = str(response["DomainStatus"]["ElasticsearchVersion"])
        esDomainEndpoint = str(response["DomainStatus"]["Endpoint"])
        try:
            response["DomainStatus"]["VPCOptions"]
            print(f"{esDomainId} is in a VPC, skipping for Shodan check")
            continue
        except KeyError:
            # use Socket to do a DNS lookup and retrieve the IP address
            esDomainIp = socket.gethostbyname(esDomainEndpoint)
            # use requests Library to check the Shodan index for your host
            r = requests.get(url=shodanUrl + esDomainIp + "?key=" + shodanApiKey)
            data = r.json()
            shodanOutput = str(data)
            if shodanOutput == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": esDomainArn
                    + "/"
                    + esDomainEndpoint
                    + "/elasticsearch-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": esDomainArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.OpenSearch.1] OpenSearch/ElasticSearch Service domains outside of a VPC should be monitored for being indexed by Shodan",
                    "Description": "OpenSearch/ElasticSearch Service domain "
                    + esDomainName
                    + " has not been indexed by Shodan.",
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Analytics",
                        "AssetService": "Amazon OpenSearch Service",
                        "AssetComponent": "Search Domain"
                    },
                    "Resources": [
                        {
                            "Type": "AwsOpenSearchDomain",
                            "Id": esDomainArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsOpenSearchDomain": {
                                    "DomainId": esDomainId,
                                    "DomainName": esDomainName,
                                    "ElasticsearchVersion": esVersion,
                                    "Endpoint": esDomainEndpoint,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": esDomainArn
                    + "/"
                    + esDomainEndpoint
                    + "/elasticsearch-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": esDomainArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.Elasticsearch.1] OpenSearch/ElasticSearch Service domains outside of a VPC should be monitored for being indexed by Shodan",
                    "Description": "ElasticSearch Service domain "
                    + esDomainName
                    + " has been indexed by Shodan on IP address "
                    + esDomainIp
                    + " from endpoint DNS name "
                    + esDomainEndpoint
                    + ". review the Shodan.io host information in the SourceUrl or ThreatIntelIndicators.SourceUrl fields for information about what ports and services are exposed and then take action to reduce exposure and harden your ES domain.",
                    "SourceUrl": "https://www.shodan.io/host/" + esDomainIp,
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Analytics",
                        "AssetService": "Amazon OpenSearch Service",
                        "AssetComponent": "Search Domain"
                    },
                    "ThreatIntelIndicators": [
                        {
                            "Type": "IPV4_ADDRESS",
                            "Category": "EXPLOIT_SITE",
                            "Value": esDomainIp,
                            "LastObservedAt": iso8601time,
                            "Source": "Shodan.io",
                            "SourceUrl": "https://www.shodan.io/host/" + esDomainIp,
                        },
                    ],
                    "Resources": [
                        {
                            "Type": "AwsElasticsearchDomain",
                            "Id": esDomainArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsElasticsearchDomain": {
                                    "DomainId": esDomainId,
                                    "DomainName": esDomainName,
                                    "ElasticsearchVersion": esVersion,
                                    "Endpoint": esDomainEndpoint,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding

@registry.register_check("aws.shodan")
def public_clb_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.ELB.1] Internet-facing Classic Load Balancers should be monitored for being indexed by Shodan"""
    elb = session.client("elb")
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    response = elb.describe_load_balancers()
    for clbs in response["LoadBalancerDescriptions"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clbs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clbName = str(clbs["LoadBalancerName"])
        clbArn = f"arn:{awsPartition}:elasticloadbalancing:{awsRegion}:{awsAccountId}:loadbalancer/{clbName}"
        clbDnsName = str(clbs["DNSName"])
        clbScheme = str(clbs["Scheme"])
        if clbScheme == "internet-facing":
            # use Socket to do a DNS lookup and retrieve the IP address
            clbIp = socket.gethostbyname(clbDnsName)
            # use requests Library to check the Shodan index for your host
            r = requests.get(url=shodanUrl + clbIp + "?key=" + shodanApiKey)
            data = r.json()
            shodanOutput = str(data)
            if shodanOutput == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clbArn
                    + "/"
                    + clbDnsName
                    + "/classic-load-balancer-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clbArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.ELB.1] Internet-facing Classic Load Balancers should be monitored for being indexed by Shodan",
                    "Description": "ElasticSearch Service domain "
                    + clbName
                    + " has not been indexed by Shodan.",
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "AWS Elastic Load Balancer",
                        "AssetComponent": "Classic Load Balancer"
                    },
                    "Resources": [
                        {
                            "Type": "AwsElbLoadBalancer",
                            "Id": clbArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"LoadBalancerName": clbName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clbArn
                    + "/"
                    + clbDnsName
                    + "/classic-load-balancer-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clbArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.ELB.1] Internet-facing Classic Load Balancers should be monitored for being indexed by Shodan",
                    "Description": "CLB "
                    + clbName
                    + " has been indexed by Shodan on IP address "
                    + clbIp
                    + " from DNS name "
                    + clbDnsName
                    + ". Review the Shodan.io host information in the SourceUrl or ThreatIntelIndicators.SourceUrl fields for information about what ports and services are exposed and then take action to reduce exposure and harden your load balancer.",
                    "SourceUrl": "https://www.shodan.io/host/" + clbIp,
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "AWS Elastic Load Balancer",
                        "AssetComponent": "Classic Load Balancer"
                    },
                    "ThreatIntelIndicators": [
                        {
                            "Type": "IPV4_ADDRESS",
                            "Category": "EXPLOIT_SITE",
                            "Value": clbIp,
                            "LastObservedAt": iso8601time,
                            "Source": "Shodan.io",
                            "SourceUrl": "https://www.shodan.io/host/" + clbIp,
                        },
                    ],
                    "Resources": [
                        {
                            "Type": "AwsElbLoadBalancer",
                            "Id": clbArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"LoadBalancerName": clbName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding

@registry.register_check("aws.shodan")
def public_dms_replication_instance_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.DMS.1] Publicly accessible Database Migration Service (DMS) Replication Instances should be monitored for being indexed by Shodan"""
    dms = session.client("dms")
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    response = dms.describe_replication_instances()
    for repinstances in response["ReplicationInstances"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(repinstances,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        dmsInstanceId = str(repinstances["ReplicationInstanceIdentifier"])
        dmsInstanceArn = str(repinstances["ReplicationInstanceArn"])
        if repinstances["PubliclyAccessible"] == True:
            dmsPublicIp = str(repinstances["ReplicationInstancePublicIpAddress"])
            # use requests Library to check the Shodan index for your host
            r = requests.get(url=shodanUrl + dmsPublicIp + "?key=" + shodanApiKey)
            data = r.json()
            shodanOutput = str(data)
            if shodanOutput == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": dmsInstanceArn
                    + "/"
                    + dmsPublicIp
                    + "/dms-replication-instance-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": dmsInstanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.DMS.1] Publicly accessible Database Migration Service (DMS) Replication Instances should be monitored for being indexed by Shodan",
                    "Description": "DMS Replication Instance "
                    + dmsInstanceId
                    + " has not been indexed by Shodan.",
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Migration & Transfer",
                        "AssetService": "AWS Database Migration Service",
                        "AssetComponent": "Replication Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsDmsReplicationInstance",
                            "Id": dmsInstanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"ReplicationInstanceId": dmsInstanceId}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": dmsInstanceArn
                    + "/"
                    + dmsPublicIp
                    + "/dms-replication-instance-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": dmsInstanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.DMS.1] Publicly accessible Database Migration Service (DMS) Replication Instances should be monitored for being indexed by Shodan",
                    "Description": "DMS Replication Instance "
                    + dmsInstanceId
                    + " has been indexed on IP address "
                    + dmsInstanceId
                    + " . Review the Shodan.io host information in the SourceUrl or ThreatIntelIndicators.SourceUrl fields for information about what ports and services are exposed and then take action to reduce exposure and harden your replication instance.",
                    "SourceUrl": "https://www.shodan.io/host/" + dmsPublicIp,
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Migration & Transfer",
                        "AssetService": "AWS Database Migration Service",
                        "AssetComponent": "Replication Instance"
                    },
                    "ThreatIntelIndicators": [
                        {
                            "Type": "IPV4_ADDRESS",
                            "Category": "EXPLOIT_SITE",
                            "Value": dmsPublicIp,
                            "LastObservedAt": iso8601time,
                            "Source": "Shodan.io",
                            "SourceUrl": "https://www.shodan.io/host/" + dmsPublicIp,
                        },
                    ],
                    "Resources": [
                        {
                            "Type": "AwsDmsReplicationInstance",
                            "Id": dmsInstanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"ReplicationInstanceId": dmsInstanceId}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
        else:
            continue

@registry.register_check("aws.shodan")
def public_amazon_mq_broker_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.AmazonMQ.1] Publicly accessible Amazon MQ message brokers should be monitored for being indexed by Shodan"""
    amzmq = session.client("mq")
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for brokers in amzmq.list_brokers(MaxResults=100)["BrokerSummaries"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(brokers,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        brokerName = str(brokers["BrokerName"])
        response = amzmq.describe_broker(BrokerId=brokerName)
        brokerArn = str(response["BrokerArn"])
        brokerId = str(response["BrokerId"])
        if response["PubliclyAccessible"] == True:
            mqInstances = response["BrokerInstances"]
            for instance in mqInstances:
                mqBrokerIpv4 = str(instance["IpAddress"])
                r = requests.get(url=shodanUrl + mqBrokerIpv4 + "?key=" + shodanApiKey)
                data = r.json()
                shodanOutput = str(data)
                if shodanOutput == "{'error': 'No information available for that IP.'}":
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": brokerArn
                        + "/"
                        + mqBrokerIpv4
                        + "/amazon-mq-broker-shodan-index-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": brokerArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Effects/Data Exposure"],
                        "CreatedAt": iso8601time,
                        "UpdatedAt": iso8601time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Title": "[Shodan.AmazonMQ.1] Publicly accessible Amazon MQ message brokers should be monitored for being indexed by Shodan",
                        "Description": "Amazon MQ message brokers "
                        + brokerName
                        + " has not been indexed by Shodan.",
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Application Integration",
                            "AssetService": "Amazon MQ",
                            "AssetComponent": "Broker"
                        },
                        "Resources": [
                            {
                                "Type": "AwsMqMessageBroker",
                                "Id": brokerArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "brokerName": brokerName,
                                        "brokerId": brokerId,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 ID.RA-2",
                                "NIST CSF V1.1 DE.AE-2",
                                "NIST SP 800-53 Rev. 4 AU-6",
                                "NIST SP 800-53 Rev. 4 CA-7",
                                "NIST SP 800-53 Rev. 4 IR-4",
                                "NIST SP 800-53 Rev. 4 PM-15",
                                "NIST SP 800-53 Rev. 4 PM-16",
                                "NIST SP 800-53 Rev. 4 SI-4",
                                "NIST SP 800-53 Rev. 4 SI-5",
                                "AIPCA TSC CC3.2",
                                "AIPCA TSC CC7.2",
                                "ISO 27001:2013 A.6.1.4",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.1",
                                "ISO 27001:2013 A.16.1.4",
                                "MITRE ATT&CK T1040",
                                "MITRE ATT&CK T1046",
                                "MITRE ATT&CK T1580",
                                "MITRE ATT&CK T1590",
                                "MITRE ATT&CK T1592",
                                "MITRE ATT&CK T1595"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": brokerArn
                        + "/"
                        + mqBrokerIpv4
                        + "/amazon-mq-broker-shodan-index-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": brokerArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Effects/Data Exposure"],
                        "CreatedAt": iso8601time,
                        "UpdatedAt": iso8601time,
                        "Severity": {"Label": "MEDIUM"},
                        "Title": "[Shodan.AmazonMQ.1] Publicly accessible Amazon MQ message brokers should be monitored for being indexed by Shodan",
                        "Description": "Amazon MQ message brokers "
                        + brokerName
                        + " has been indexed by Shodan on IP address "
                        + mqBrokerIpv4
                        + ".",
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Application Integration",
                            "AssetService": "Amazon MQ",
                            "AssetComponent": "Broker"
                        },
                        "Resources": [
                            {
                                "Type": "AwsMqMessageBroker",
                                "Id": brokerArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "brokerName": brokerName,
                                        "brokerId": brokerId,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 ID.RA-2",
                                "NIST CSF V1.1 DE.AE-2",
                                "NIST SP 800-53 Rev. 4 AU-6",
                                "NIST SP 800-53 Rev. 4 CA-7",
                                "NIST SP 800-53 Rev. 4 IR-4",
                                "NIST SP 800-53 Rev. 4 PM-15",
                                "NIST SP 800-53 Rev. 4 PM-16",
                                "NIST SP 800-53 Rev. 4 SI-4",
                                "NIST SP 800-53 Rev. 4 SI-5",
                                "AIPCA TSC CC3.2",
                                "AIPCA TSC CC7.2",
                                "ISO 27001:2013 A.6.1.4",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.1",
                                "ISO 27001:2013 A.16.1.4",
                                "MITRE ATT&CK T1040",
                                "MITRE ATT&CK T1046",
                                "MITRE ATT&CK T1580",
                                "MITRE ATT&CK T1590",
                                "MITRE ATT&CK T1592",
                                "MITRE ATT&CK T1595"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding

@registry.register_check("aws.shodan")
def cloudfront_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.CloudFront.1] CloudFront Distributions should be monitored for being indexed by Shodan"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    paginator = cloudfront.get_paginator("list_distributions")
    iterator = paginator.paginate()
    for page in iterator:
        for cfront in page["DistributionList"]["Items"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(cfront,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            domainName = str(cfront["DomainName"])
            cfArn = str(cfront["ARN"])
            cfId = str(cfront["Id"])
            cfDomainIp = socket.gethostbyname(domainName)
            # use requests Library to check the Shodan index for your host
            r = requests.get(url=shodanUrl + cfDomainIp + "?key=" + shodanApiKey)
            data = r.json()
            shodanOutput = str(data)
            if shodanOutput == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": cfArn + "/" + domainName + "/cloudfront-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": cfArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.CloudFront.1] CloudFront Distributions should be monitored for being indexed by Shodan",
                    "Description": "CloudFront Distribution "
                    + cfId
                    + " has not been indexed by Shodan.",
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon CloudFront",
                        "AssetComponent": "Distribution"
                    },
                    "Resources": [
                        {
                            "Type": "AwsCloudFrontDistribution",
                            "Id": cfArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsCloudFrontDistribution": {
                                    "DomainName": domainName
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": cfArn + "/" + domainName + "/cloudfront-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": cfArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.CloudFront.1] CloudFront Distributions should be monitored for being indexed by Shodan",
                    "Description": "CloudFront Distribution "
                    + cfId
                    + " has been indexed by Shodan on IP Address (from Domain Name) "
                    + cfDomainIp
                    + ". review the Shodan.io host information in the SourceUrl or ThreatIntelIndicators.SourceUrl fields for information about what ports and services are exposed and then take action to reduce exposure and harden your host.",
                    "SourceUrl": "https://www.shodan.io/host/" + cfDomainIp,
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon CloudFront",
                        "AssetComponent": "Distribution"
                    },
                    "ThreatIntelIndicators": [
                        {
                            "Type": "IPV4_ADDRESS",
                            "Category": "EXPLOIT_SITE",
                            "Value": cfDomainIp,
                            "LastObservedAt": iso8601time,
                            "Source": "Shodan.io",
                            "SourceUrl": "https://www.shodan.io/host/" + cfDomainIp,
                        },
                    ],
                    "Resources": [
                        {
                            "Type": "AwsCloudFrontDistribution",
                            "Id": cfArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsCloudFrontDistribution": {
                                    "DomainName": domainName
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding

@registry.register_check("aws.shodan")
def global_accelerator_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.GlobalAccelerator.1] Accelerators should be monitored for being indexed by Shodan"""
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Create a Session is us-west-2 - which is where the Global Accelerator API is in
    session = session.Session(region_name="us-west-2")
    gax = session.client("globalaccelerator")
    paginator = gax.get_paginator("list_accelerators")
    iterator = paginator.paginate()
    for page in iterator:
        for ga in page["Accelerators"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(ga,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            gaxArn = str(ga["AcceleratorArn"])
            gaxName = str(ga["Name"])
            gaxDns = str(ga["DnsName"])
            gaxDomainIp = socket.gethostbyname(gaxDns)
            # use requests Library to check the Shodan index for your host
            r = requests.get(url=shodanUrl + gaxDomainIp + "?key=" + shodanApiKey)
            data = r.json()
            shodanOutput = str(data)
            if shodanOutput == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": gaxArn + "/" + gaxDns + "/global-accelerator-shodan-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": gaxArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.GlobalAccelerator.1] Accelerators should be monitored for being indexed by Shodan",
                    "Description": "Accelerator "
                    + gaxName
                    + " has not been indexed by Shodan.",
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon Global Accelerator",
                        "AssetComponent": "Accelerator"
                    },
                    "Resources": [
                        {
                            "Type": "AwsGlobalAcceleratorAccelerator",
                            "Id": gaxArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "Name": gaxName,
                                    "DnsName": gaxDns
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": gaxArn + "/" + gaxDns + "/global-accelerator-shodan-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": gaxArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.GlobalAccelerator.1] Accelerators should be monitored for being indexed by Shodan",
                    "Description": "Accelerator "
                    + gaxName
                    + " has been indexed by Shodan on IP Address (from DNS Name) "
                    + gaxDomainIp
                    + ". review the Shodan.io host information in the SourceUrl or ThreatIntelIndicators.SourceUrl fields for information about what ports and services are exposed and then take action to reduce exposure and harden your host.",
                    "SourceUrl": "https://www.shodan.io/host/" + gaxDomainIp,
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon Global Accelerator",
                        "AssetComponent": "Accelerator"
                    },
                    "ThreatIntelIndicators": [
                        {
                            "Type": "IPV4_ADDRESS",
                            "Category": "EXPLOIT_SITE",
                            "Value": gaxDomainIp,
                            "LastObservedAt": iso8601time,
                            "Source": "Shodan.io",
                            "SourceUrl": "https://www.shodan.io/host/" + gaxDomainIp,
                        },
                    ],
                    "Resources": [
                        {
                            "Type": "AwsGlobalAcceleratorAccelerator",
                            "Id": gaxArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "Name": gaxName,
                                    "DnsName": gaxDns
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding