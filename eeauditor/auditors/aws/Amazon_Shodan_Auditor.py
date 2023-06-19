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
from botocore.config import Config

# Adding backoff and retries for SSM - this API gets throttled a lot
config = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'adaptive'
   }
)

registry = CheckRegister()

SHODAN_HOSTS_URL = "https://api.shodan.io/shodan/host/"

def get_shodan_api_key(cache):

    response = cache.get("get_shodan_api_key")
    if response:
        return response

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
                print(f"Error retrieving API Key from SSM, skipping all Shodan checks, error: {e}")
                apiKey = None

        # Retrieve the credential from AWS Secrets Manager
        elif credLocation == "AWS_SECRETS_MANAGER":
            try:
                apiKey = asm.get_secret_value(
                    SecretId=shodanCredValue,
                )["SecretString"]
            except ClientError as e:
                print(f"Error retrieving API Key from ASM, skipping all Shodan checks, error: {e}")
                apiKey = None
        
    cache["get_shodan_api_key"] = apiKey
    return cache["get_shodan_api_key"]

def google_dns_resolver(target):
    """
    Accepts a Public DNS name and attempts to use Google's DNS A record resolver to determine an IP address
    """
    url = f"https://dns.google/resolve?name={target}&type=A"
    
    r = requests.get(url=url)
    if r.status_code != 200:
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
    response = cache.get("describe_instances")
    if response:
        return response
    
    instanceList = []
    
    ec2 = session.client("ec2")
    ssm = session.client("ssm", config=config)
    # Enrich EC2 with SSM details - this is done for the EC2 Auditor - all others using EC2 don't matter too much
    managedInstances = ssm.describe_instance_information()["InstanceInformationList"]

    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[
                {
                    "Name": "instance-state-name",
                    "Values": [ 
                        "running",
                        "stopped" 
                    ]
                }
            ]
        ):
        for r in page["Reservations"]:
            for i in r["Instances"]:
                # Use a list comprehension to attempt to get SSM info for the instance
                managedInstanceInfo = [mnginst for mnginst in managedInstances if mnginst["InstanceId"] == i["InstanceId"]]
                i["ManagedInstanceInformation"] = managedInstanceInfo
                instanceList.append(i)

        cache["describe_instances"] = instanceList
        return cache["describe_instances"]

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
                        "sqlserver-web"
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

















