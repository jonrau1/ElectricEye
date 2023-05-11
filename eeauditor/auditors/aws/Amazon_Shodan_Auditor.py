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

import tomli
import os
import sys
import boto3
import requests
import ipaddress
import datetime
import base64
import json
from botocore.exceptions import ClientError
from check_register import CheckRegister

registry = CheckRegister()

SHODAN_HOSTS_URL = "https://api.shodan.io/shodan/host/"

def get_shodan_api_key():
    validCredLocations = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

    # Get the absolute path of the current directory
    currentDir = os.path.abspath(os.path.dirname(__file__))
    # Go two directories back to /eeauditor/
    twoBack = os.path.abspath(os.path.join(currentDir, "../../"))

    # TOML is located in /eeauditor/ directory
    tomlFile = f"{twoBack}/external_providers.toml"
    with open(tomlFile, "rb") as f:
        data = tomli.load(f)

    # Parse from [global] to determine credential location of PostgreSQL Password
    credLocation = data["global"]["credentials_location"]
    shodanCredValue = data["global"]["shodan_api_key_value"]
    if credLocation not in validCredLocations:
        print(f"Invalid option for [global.credLocation]. Must be one of {str(validCredLocations)}.")
        sys.exit(2)
    if not shodanCredValue:
        apiKey = None
    else:

        # Boto3 Clients
        ssm = boto3.client("ssm")
        asm = boto3.client("secretsmanager")

        # Retrieve API Key
        if credLocation == "CONFIG_FILE":
            apiKey = shodanCredValue

        # Retrieve the credential from SSM Parameter Store
        elif credLocation == "AWS_SSM":
            
            try:
                apiKey = ssm.get_parameter(
                    Name=shodanCredValue,
                    WithDecryption=True
                )["Parameter"]["Value"]
            except ClientError as e:
                raise e

        # Retrieve the credential from AWS Secrets Manager
        elif credLocation == "AWS_SECRETS_MANAGER":
            try:
                apiKey = asm.get_secret_value(
                    SecretId=shodanCredValue,
                )["SecretString"]
            except ClientError as e:
                raise e
        
    return apiKey

def google_dns_resolver(target):
    """
    Accepts a Public DNS name and attempts to use Google's DNS A record resolver to determine an IP address
    """
    url = f"https://dns.google/resolve?name={target}&type=A"
    
    r = requests.get(url=url)
    if r.status_code != 200 or 201:
        return None
    else:
        for result in json.loads(r.text)["Answer"]:
            try:
                if not (
                    ipaddress.IPv4Address(result["data"]).is_private
                    or ipaddress.IPv4Address(result["data"]).is_loopback
                    or ipaddress.IPv4Address(result["data"]).is_link_local
                ):
                    return result["data"]
                else:
                    continue
            except ipaddress.AddressValueError:
                continue
        # if the loop terminates without any result return None
        return None

def describe_instances(cache, session):
    ec2 = session.client("ec2")
    instanceList = []
    response = cache.get("instances")
    if response:
        return response
    
    paginator = ec2.get_paginator("describe_instances")
    if paginator:
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name","Values": ["running"]}]):
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    instanceList.append(i)

        cache["instances"] = instanceList
        return cache["instances"]
    
def describe_load_balancers(cache, session):
    elbv2 = session.client("elbv2")
    # loop through ELBv2 load balancers
    response = cache.get("describe_load_balancers")
    if response:
        return response
    cache["describe_load_balancers"] = elbv2.describe_load_balancers()
    return cache["describe_load_balancers"]

def describe_db_instances(cache, session):
    rds = session.client("rds")
    dbInstances = []
    response = cache.get("describe_db_instances")
    if response:
        return response
    paginator = rds.get_paginator('describe_db_instances')
    if paginator:
        for page in paginator.paginate(
            Filters=[
                {
                    "Name": "engine",
                    "Values": [
                        "aurora-mysql",
                        "aurora-postgresql",
                        "mariadb",
                        "mysql",
                        "oracle-ee",
                        "oracle-ee-cdb",
                        "oracle-se2",
                        "oracle-se2-cdb",
                        "postgres",
                        "sqlserver-ee",
                        "sqlserver-se",
                        "sqlserver-ex",
                        "sqlserver-web",
                        "custom-sqlserver-ee",
                        "custom-sqlserver-se",
                        "custom-sqlserver-web"
                    ]
                }
            ]
        ):
            for dbinstance in page["DBInstances"]:
                dbInstances.append(dbinstance)
    cache["describe_db_instances"] = dbInstances
    return cache["describe_db_instances"]

def list_domain_names(cache, session):
    domainDetails = []
    
    response = cache.get("list_domain_names")
    if response:
        return response
    
    elasticsearch = session.client("es")
    for domain in elasticsearch.list_domain_names()["DomainNames"]:
        domainDetails.append(
            elasticsearch.describe_elasticsearch_domain(
                DomainName=domain
            )
        )

    cache["list_domain_names"] = domainDetails
    return cache["list_domain_names"]

def describe_clbs(cache, session):
    elb = session.client("elb")
    # loop through ELB load balancers
    response = cache.get("describe_load_balancers")
    if response:
        return response
    cache["describe_load_balancers"] = elb.describe_load_balancers()
    return cache["describe_load_balancers"]

def describe_replication_instances(cache, session):
    dms = session.client("dms")
    response = cache.get("describe_replication_instances")
    if response:
        return response
    cache["describe_replication_instances"] = dms.describe_replication_instances()
    return cache["describe_replication_instances"]

def list_brokers(cache, session):
    amazonMqBrokerDetails = []

    response = cache.get("list_brokers")
    if response:
        return response
    
    amzmq = session.client("mq")
    for broker in amzmq.list_brokers(MaxResults=100)["BrokerSummaries"]:
        amazonMqBrokerDetails.append(
            amzmq.describe_broker(
                BrokerId=broker["BrokerName"]
            )
        )

    cache["list_brokers"] = amazonMqBrokerDetails
    return cache["list_brokers"]

def paginate_distributions(cache, session):
    cloudfront = session.client("cloudfront")

    itemList = []
    response = cache.get("items")
    if response:
        return response
    paginator = cloudfront.get_paginator("list_distributions")
    if paginator:
        for page in paginator.paginate():
            try:
                for items in page["DistributionList"]["Items"]:
                    itemList.append(items)
            except KeyError:
                return {}
        cache["items"] = itemList
        return cache["items"]

@registry.register_check("ec2")
def public_ec2_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.EC2.1] EC2 instances with public IP addresses should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key()
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in describe_instances(cache, session):
        if shodanApiKey == None:
            continue
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        ec2Type = str(i["InstanceType"])
        ec2AmiId = str(i["ImageId"])
        ec2Id = str(i["InstanceId"])
        ec2Arn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}instance/{ec2Id}"
        ec2VpcId = str(i["VpcId"])
        ec2SubnetId = str(i["SubnetId"])
        try:
            ec2PublicIp = str(i["PublicIpAddress"])
        except KeyError:
            continue
        # check if IP indexed by Shodan
        r = requests.get(url=f"{SHODAN_HOSTS_URL}{ec2PublicIp}?key={shodanApiKey}").json()
        if str(r) == "{'error': 'No information available for that IP.'}":
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ec2Arn}/{ec2PublicIp}/ec2-shodan-index-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": ec2Arn,
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601time,
                "UpdatedAt": iso8601time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Title": "[Shodan.EC2.1] EC2 instances with public IP addresses should be monitored for being indexed by Shodan",
                "Description": f"EC2 instance {ec2AmiId} has not been indexed by Shodan.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                        "Url": SHODAN_HOSTS_URL
                    }
                },
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
            assetPayload = {
                "Instance": i,
                "Shodan": r
            }
            assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ec2Arn}/{ec2PublicIp}/ec2-shodan-index-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": ec2Arn,
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601time,
                "UpdatedAt": iso8601time,
                "Severity": {"Label": "MEDIUM"},
                "Title": "[Shodan.EC2.1] EC2 instances with public IP addresses should be monitored for being indexed by Shodan",
                "Description": f"EC2 instance {ec2Id} has been indexed by Shodan on IP {ec2PublicIp}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                        "Url": f"{SHODAN_HOSTS_URL}{ec2PublicIp}"
                    }
                },
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
                                "VpcId": ec2VpcId,
                                "SubnetId": ec2SubnetId,
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

@registry.register_check("elasticloadbalancing")
def public_alb_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.ELBv2.1] Internet-facing Application Load Balancers should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key()
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for lb in describe_load_balancers(cache, session)["LoadBalancers"]:
        if shodanApiKey == None:
            continue
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Arn = str(lb["LoadBalancerArn"])
        elbv2Name = str(lb["LoadBalancerName"])
        elbv2DnsName = str(lb["DNSName"])
        elbv2LbType = str(lb["Type"])
        elbv2Scheme = str(lb["Scheme"])
        elbv2VpcId = str(lb["VpcId"])
        if (elbv2Scheme == "internet-facing" and elbv2LbType == "application"):
            # Use Google DNS to resolve
            elbv2Ip = google_dns_resolver(elbv2DnsName)
            if elbv2Ip is None:
                continue
            # check if IP indexed by Shodan
            r = requests.get(url=f"{SHODAN_HOSTS_URL}{elbv2Ip}?key={shodanApiKey}").json()
            if str(r) == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{elbv2Arn}/{elbv2DnsName}/alb-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": elbv2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.ELBv2.1] Internet-facing Application Load Balancers should be monitored for being indexed by Shodan",
                    "Description": f"Application load balancer {elbv2Name} has not been indexed by Shodan.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": SHODAN_HOSTS_URL
                        }
                    },
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
                                    "DNSName": elbv2DnsName,
                                    "Scheme": elbv2Scheme,
                                    "Type": elbv2LbType,
                                    "VpcId": elbv2VpcId,
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
                assetPayload = {
                    "LoadBalancer": lb,
                    "Shodan": r
                }
                assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{elbv2Arn}/{elbv2DnsName}/alb-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": elbv2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.ELBv2.1] Internet-facing Application Load Balancers should be monitored for being indexed by Shodan",
                    "Description": f"Application load balancer {elbv2Name} has been indexed by Shodan on IP address {elbv2Ip} - resolved from ALB DNS {elbv2DnsName}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": f"{SHODAN_HOSTS_URL}{elbv2Ip}"
                        }
                    },
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
                                    "DNSName": elbv2DnsName,
                                    "Scheme": elbv2Scheme,
                                    "Type": elbv2LbType,
                                    "VpcId": elbv2VpcId,
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

@registry.register_check("rds")
def public_rds_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.RDS.1] Public accessible RDS instances should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key()
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for rdsdb in describe_db_instances(cache, session):
        if shodanApiKey == None:
            continue
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
            # Use Google DNS to resolve
            rdsIp = google_dns_resolver(rdsDns)
            if rdsIp is None:
                continue
            # check if IP indexed by Shodan
            r = requests.get(url=f"{SHODAN_HOSTS_URL}{rdsIp}?key={shodanApiKey}").json()
            if str(r) == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{rdsInstanceArn}/{rdsDns}/rds-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": rdsInstanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.RDS.1] Public accessible RDS instances should be monitored for being indexed by Shodan",
                    "Description": f"RDS instance {rdsInstanceId} has not been indexed by Shodan.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": SHODAN_HOSTS_URL
                        }
                    },
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
                assetPayload = {
                    "DbInstance": rdsdb,
                    "Shodan": r
                }
                assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{rdsInstanceArn}/{rdsDns}/rds-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": rdsInstanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.RDS.1] Public accessible RDS instances should be monitored for being indexed by Shodan",
                    "Description": f"RDS instance {rdsInstanceId} has been indexed by Shodan on IP address {rdsIp} - resolved from RDS endpoint DNS {rdsDns}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": f"{SHODAN_HOSTS_URL}{rdsIp}"
                        }
                    },
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

@registry.register_check("es")
def public_es_domain_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.Elasticsearch.1] OpenSearch/ElasticSearch Service domains outside of a VPC should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key()
    elasticsearch = session.client("es")
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for domain in list_domain_names(cache, session):
        if shodanApiKey == None:
            continue
        esDomain = str(domain["DomainName"])
        response = elasticsearch.describe_elasticsearch_domain(DomainName=esDomain)["DomainStatus"]
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        esDomainId = str(response["DomainId"])
        esDomainName = str(response["DomainName"])
        esDomainArn = str(response["ARN"])
        esVersion = str(response["ElasticsearchVersion"])
        esDomainEndpoint = str(response["Endpoint"])
        try:
            response["VPCOptions"]
            continue
        except KeyError:
            # Use Google DNS to resolve
            esDomainIp = google_dns_resolver(esDomainEndpoint)
            if esDomainIp is None:
                continue
            # check if IP indexed by Shodan
            r = requests.get(url=f"{SHODAN_HOSTS_URL}{esDomainIp}?key={shodanApiKey}").json()
            if str(r) == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{esDomainArn}/{esDomainEndpoint}/elasticsearch-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": esDomainArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.Elasticsearch.1] OpenSearch/ElasticSearch Service domains outside of a VPC should be monitored for being indexed by Shodan",
                    "Description": f"OpenSearch/ElasticSearch Service domain {esDomainName} has not been indexed by Shodan.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": SHODAN_HOSTS_URL
                        }
                    },
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
                assetPayload = {
                    "Domain": response,
                    "Shodan": r
                }
                assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{esDomainArn}/{esDomainEndpoint}/elasticsearch-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": esDomainArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.Elasticsearch.1] OpenSearch/ElasticSearch Service domains outside of a VPC should be monitored for being indexed by Shodan",
                    "Description": f"ElasticSearch/OpenSearch Service domain {esDomainName} has been indexed by Shodan on IP address on {esDomainIp} - resolved from endpoint DNS {esDomainEndpoint}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": f"{SHODAN_HOSTS_URL}{esDomainIp}"
                        }
                    },
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

@registry.register_check("elasticloadbalancing")
def public_clb_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.ELB.1] Internet-facing Classic Load Balancers should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key()
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for clbs in describe_clbs(cache, session)["LoadBalancerDescriptions"]:
        if shodanApiKey == None:
            continue
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(clbs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clbName = str(clbs["LoadBalancerName"])
        clbArn = f"arn:{awsPartition}:elasticloadbalancing:{awsRegion}:{awsAccountId}:loadbalancer/{clbName}"
        clbDnsName = str(clbs["DNSName"])
        clbScheme = str(clbs["Scheme"])
        if clbScheme == "internet-facing":
            # Use Google DNS to resolve
            clbIp = google_dns_resolver(clbDnsName)
            if clbIp is None:
                continue
            # check if IP indexed by Shodan
            r = requests.get(url=f"{SHODAN_HOSTS_URL}{clbIp}?key={shodanApiKey}").json()
            if str(r) == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{clbArn}/{clbDnsName}/classic-load-balancer-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clbArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.ELB.1] Internet-facing Classic Load Balancers should be monitored for being indexed by Shodan",
                    "Description": f"Classic Load Balancer {clbName} has not been indexed by Shodan.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": SHODAN_HOSTS_URL
                        }
                    },
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
                assetPayload = {
                    "LoadBalancer": clbs,
                    "Shodan": r
                }
                assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{clbArn}/{clbDnsName}/classic-load-balancer-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clbArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.ELB.1] Internet-facing Classic Load Balancers should be monitored for being indexed by Shodan",
                    "Description": f"Classic Load Balancer {clbName} has been indexed by Shodan on IP address {clbIp} - resolved from DNS name {clbDnsName}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": f"{SHODAN_HOSTS_URL}{clbIp}"
                        }
                    },
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
                            "Details": {"Other": {"LoadBalancerName": clbName}}
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

@registry.register_check("dms")
def public_dms_replication_instance_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.DMS.1] Publicly accessible Database Migration Service (DMS) Replication Instances should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key()
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for ri in describe_replication_instances(cache, session)["ReplicationInstances"]:
        if shodanApiKey == None:
            continue
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(ri,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        dmsInstanceId = str(ri["ReplicationInstanceIdentifier"])
        dmsInstanceArn = str(ri["ReplicationInstanceArn"])
        if ri["PubliclyAccessible"] == True:
            dmsPublicIp = str(ri["ReplicationInstancePublicIpAddress"])
            # check if IP indexed by Shodan
            r = requests.get(url=f"{SHODAN_HOSTS_URL}{dmsPublicIp}?key={shodanApiKey}").json()
            if str(r) == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{dmsInstanceArn}/{dmsPublicIp}/dms-replication-instance-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": dmsInstanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.DMS.1] Publicly accessible Database Migration Service (DMS) Replication Instances should be monitored for being indexed by Shodan",
                    "Description": f"DMS Replication Instance {dmsInstanceId} has not been indexed by Shodan.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": SHODAN_HOSTS_URL
                        }
                    },
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
                            "Details": {"Other": {"ReplicationInstanceId": dmsInstanceId}}
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
                assetPayload = {
                    "ReplicationInstance": ri,
                    "Shodan": r
                }
                assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{dmsInstanceArn}/{dmsPublicIp}/dms-replication-instance-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": dmsInstanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.DMS.1] Publicly accessible Database Migration Service (DMS) Replication Instances should be monitored for being indexed by Shodan",
                    "Description": f"DMS Replication Instance {dmsInstanceId} has been indexed on IP address {dmsPublicIp}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": f"{SHODAN_HOSTS_URL}{dmsPublicIp}"
                        }
                    },
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

@registry.register_check("mq")
def public_amazon_mq_broker_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.AmazonMQ.1] Publicly accessible Amazon MQ message brokers should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key()
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for brokers in list_brokers(cache, session):
        if shodanApiKey == None:
            continue
        brokerName = str(brokers["BrokerName"])
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(brokers,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        brokerArn = str(brokers["BrokerArn"])
        brokerId = str(brokers["BrokerId"])
        if brokers["PubliclyAccessible"] == True:
            try:
                consoleHostname = brokers["BrokerInstances"][0]["ConsoleURL"].split("https://")[1].split(":")[0]
            except KeyError:
                continue
            try:
                mqBrokerIpv4 = google_dns_resolver(consoleHostname)
            except KeyError:
                continue
            r = requests.get(url=f"{SHODAN_HOSTS_URL}{mqBrokerIpv4}?key={shodanApiKey}").json()
            if str(r) == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{brokerArn}/{mqBrokerIpv4}/amazon-mq-broker-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.AmazonMQ.1] Publicly accessible Amazon MQ message brokers should be monitored for being indexed by Shodan",
                    "Description": f"Amazon MQ message broker {brokerName} has not been indexed by Shodan.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": SHODAN_HOSTS_URL
                        }
                    },
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
                                    "BrokerName": brokerName,
                                    "BrokerId": brokerId,
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
                assetPayload = {
                    "Broker": brokers,
                    "Shodan": r
                }
                assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{brokerArn}/{mqBrokerIpv4}/amazon-mq-broker-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.AmazonMQ.1] Publicly accessible Amazon MQ message brokers should be monitored for being indexed by Shodan",
                    "Description": f"AmazonMQ Broker {brokerName} has been indexed on IP address {mqBrokerIpv4}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": f"{SHODAN_HOSTS_URL}{mqBrokerIpv4}"
                        }
                    },
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
                                    "BrokerName": brokerName,
                                    "BrokerId": brokerId,
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

@registry.register_check("cloudfront")
def cloudfront_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.CloudFront.1] CloudFront Distributions should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key()
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cfront in paginate_distributions(cache, session):
        if shodanApiKey == None:
            continue
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cfront,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        domainName = str(cfront["DomainName"])
        cfArn = str(cfront["ARN"])
        cfId = str(cfront["Id"])
        # Use Google DNS to resolve
        cfDomainIp = google_dns_resolver(domainName)
        if cfDomainIp is None:
            continue
        # check if IP indexed by Shodan
        r = requests.get(url=f"{SHODAN_HOSTS_URL}{cfDomainIp}?key={shodanApiKey}").json()
        if str(r) == "{'error': 'No information available for that IP.'}":
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{cfArn}/{domainName}/cloudfront-shodan-index-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": cfArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601time,
                "UpdatedAt": iso8601time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Title": "[Shodan.CloudFront.1] CloudFront Distributions should be monitored for being indexed by Shodan",
                "Description": f"CloudFront Distribution {cfId} has not been indexed by Shodan.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                        "Url": SHODAN_HOSTS_URL
                    }
                },
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
            assetPayload = {
                "Distribution": cfront,
                "Shodan": r
            }
            assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{cfArn}/{domainName}/cloudfront-shodan-index-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": cfArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601time,
                "UpdatedAt": iso8601time,
                "Severity": {"Label": "MEDIUM"},
                "Title": "[Shodan.CloudFront.1] CloudFront Distributions should be monitored for being indexed by Shodan",
                "Description": f"CloudFront Distribution {cfId} has been indexed by Shodan on IP address {cfDomainIp} - resolved from DNS name {domainName}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                        "Url": f"{SHODAN_HOSTS_URL}{cfDomainIp}"
                    }
                },
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

@registry.register_check("globalaccelerator")
def global_accelerator_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Shodan.GlobalAccelerator.1] Accelerators should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key()
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    gax = session.client("globalaccelerator", region_name="us-west-2")
    for page in gax.get_paginator("list_accelerators").paginate():
        if shodanApiKey == None:
            continue
        for ga in page["Accelerators"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(ga,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            gaxArn = str(ga["AcceleratorArn"])
            gaxName = str(ga["Name"])
            gaxDns = str(ga["DnsName"])
            gaxDomainIp = google_dns_resolver(gaxDns)
            if gaxDomainIp is None:
                continue
            # check if IP indexed by Shodan
            r = requests.get(url=f"{SHODAN_HOSTS_URL}{gaxDomainIp}?key={shodanApiKey}").json()
            if str(r) == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{gaxArn}/{gaxDns}/global-accelerator-shodan-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": gaxArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[Shodan.GlobalAccelerator.1] Accelerators should be monitored for being indexed by Shodan",
                    "Description": f"Accelerator {gaxName} has not been indexed by Shodan.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": SHODAN_HOSTS_URL
                        }
                    },
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
                assetPayload = {
                    "Accelerator": ga,
                    "Shodan": r
                }
                assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{gaxArn}/{gaxDns}/global-accelerator-shodan-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": gaxArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[Shodan.GlobalAccelerator.1] Accelerators should be monitored for being indexed by Shodan",
                    "Description": f"Accelerator {gaxName} has been indexed by Shodan on IP address {gaxDomainIp} - resolved from DNS name {gaxDns}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": f"{SHODAN_HOSTS_URL}{gaxDomainIp}"
                        }
                    },
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