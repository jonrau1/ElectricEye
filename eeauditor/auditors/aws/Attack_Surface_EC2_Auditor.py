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

import json
import boto3
import nmap3
import datetime
from check_register import CheckRegister
from dateutil.parser import parse

registry = CheckRegister()

ec2 = boto3.client("ec2")
nmap = nmap3.Nmap()

def paginate(cache):
    instanceList = []
    response = cache.get("instances")
    if response:
        return response
    paginator = ec2.get_paginator("describe_instances")
    if paginator:
        for page in paginator.paginate(Filters=[{'Name': 'instance-state-name','Values': ['running']}]):
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    instanceList.append(i)
        cache["instances"] = instanceList
        return cache["instances"]

def scan_host(host_ip):
    # This function carries out the scanning of EC2 instances
    # Nmap scan top 10 ports without ping probe
    results = nmap.scan_top_ports(
        host_ip,
        args="-Pn --script http-title.nse,http-server-header.nse"
    )

    print(f"Scanning {host_ip}")

    try:
        port21 = results[host_ip]['ports'][0]['state']
        port22 = results[host_ip]['ports'][1]['state']
        port23 = results[host_ip]['ports'][2]['state']
        port25 = results[host_ip]['ports'][3]['state']
        port80 = results[host_ip]['ports'][4]['state']
        if str(results[host_ip]['ports'][4]['scripts']) == '[]':
            httpServerHeaderResponse = 'NO_DATA'
            httpTitleResponse = 'NO_DATA'
        else:
            for script in results[host_ip]['ports'][4]['scripts']:
                if str(script['name']) == 'http-server-header':
                    httpServerHeaderResponse = str(script['raw'])
                elif str(script['name']) == 'http-title':
                    httpTitleResponse = str(script['raw'])
                else:
                    pass
        port110 = results[host_ip]['ports'][5]['state']
        port139 = results[host_ip]['ports'][6]['state']
        port443 = results[host_ip]['ports'][7]['state']
        if str(results[host_ip]['ports'][7]['scripts']) == '[]':
            httpServerHeaderResponse = 'NO_DATA'
            httpTitleResponse = 'NO_DATA'
        else:
            for script in results[host_ip]['ports'][7]['scripts']:
                if str(script['name']) == 'http-server-header':
                    httpsServerHeaderResponse = str(script['raw'])
                elif str(script['name']) == 'http-title':
                    httpsTitleResponse = str(script['raw'])
                else:
                    pass
        port445 = results[host_ip]['ports'][8]['state']
        port3389 = results[host_ip]['ports'][9]['state']
    except KeyError:
        results = None

    return results

@registry.register_check("ec2")
def ec2_attack_surface_open_top10nmap_port_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.1] EC2 Instances should not be internet-facing"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # Paginate the iterator object from Cache
    for i in paginate(cache=cache):
        instanceId = str(i["InstanceId"])
        instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        
        # If Public DNS or Public IP are empty it means the instance is not public, we can skip this
        try:
            hostIp = i["PublicIpAddress"]
            if hostIp == ("" or None):
                continue
        except KeyError:
            continue
        else:
            scanner = scan_host(hostIp)
            print(json.dumps(scanner,indent=2,default=str))
            # NoneType returned on KeyError due to Nmap errors
            if scanner == None:
                continue

            # create Sec Hub finding

            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/attack-surface-ec2-open-port-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices/Network Reachability",
                    "TTPs/Discovery"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[AttackSurface.EC2.1] EC2 Instances should not be internet-facing",
                "Description": "EC2 Instance "
                + instanceId
                + " is internet-facing (due to having a Public DNS), instances should be behind Load Balancers or CloudFront distrobutions to avoid any vulnerabilities on the middleware or the operating system from being exploited directly and to increase high availability and resilience of applications hosted on EC2. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "EC2 Instances should be rebuilt in Private Subnets within your VPC and placed behind Load Balancers. To learn how to attach Instances to a public-facing load balancer refer to the How do I attach backend instances with private IP addresses to my internet-facing load balancer in ELB? post within the AWS Premium Support Knowledge Center",
                        "Url": "https://aws.amazon.com/premiumsupport/knowledge-center/public-load-balancer-private-ec2/"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-3",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-17",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-20",
                        "NIST SP 800-53 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding