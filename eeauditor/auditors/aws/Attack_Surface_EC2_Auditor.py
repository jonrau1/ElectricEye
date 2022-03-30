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
import nmap3
import datetime
from check_register import CheckRegister
from dateutil.parser import parse

registry = CheckRegister()

ec2 = boto3.client("ec2")
nmap = nmap3.NmapScanTechniques()

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

def scan_host(host_ip, instance_id):
    # This function carries out the scanning of EC2 instances using TCP without service fingerprinting
    # runs Top 10 (minus HTTPS) as well as various DB/Cache/Docker/K8s/NFS/SIEM ports
    try:
        results = nmap.nmap_tcp_scan(
            host_ip,
            args="-Pn -p 21,22,23,25,80,110,139,445,3389,1433,3306,2049,2375,1521,5432,5601,8182,8080,8089,10250,6379,9092,27017"
        )

        print(f"Scanning EC2 instance {instance_id} on {host_ip}")
        return results
    except KeyError:
        results = None

@registry.register_check("ec2")
def ec2_attack_surface_open_tcp_port_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AttackSurface.EC2.{checkIdNumber}] EC2 Instances should not have a publicly reachable {serviceName} service"""
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
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        # If Public DNS or Public IP are empty it means the instance is not public, we can skip this
        try:
            hostIp = i["PublicIpAddress"]
            if hostIp == ("" or None):
                continue
        except KeyError:
            continue
        else:
            scanner = scan_host(hostIp, instanceId)
            # NoneType returned on KeyError due to Nmap errors
            if scanner == None:
                continue
            else:
                # Loop the results of the scan - starting with Open Ports which require a combination of
                # a Public Instance, an open SG rule, and a running service/server on the host itself
                # use enumerate and a fixed offset to product the Check Title ID number
                for index, p in enumerate(scanner[hostIp]["ports"]):
                    # Parse out the Protocol, Port, Service, and State/State Reason from NMAP Results
                    checkIdNumber = str(int(index + 1))
                    portNumber = int(p["portid"])
                    if portNumber == 8089:
                        serviceName = 'SPLUNKD'
                    elif portNumber == 10250:
                        serviceName = 'KUBERNETES-API'
                    else:
                        serviceName = str(p["service"]["name"]).upper()
                    serviceStateReason = str(p["reason"])
                    serviceState = str(p["state"])
                    # This is a failing check
                    if serviceState == "open":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{instanceArn}/attack-surface-ec2-open-{serviceName}-check",
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
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": f"[AttackSurface.EC2.{checkIdNumber}] EC2 Instances should not be publicly reachable on {serviceName}",
                            "Description": f"EC2 instance {instanceId} is publicly reachable on port {portNumber} which corresponds to the {serviceName} service. When Services are successfully fingerprinted by the ElectricEye Attack Surface Management Auditor it means the instance is Public, has an open Secuirty Group rule, and a running service on the host which adversaries can also see. Refer to the remediation insturctions for an example of a way to secure EC2 instances.",
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
                                            "SubnetId": subnetId,
                                            "LaunchedAt": parse(instanceLaunchedAt).isoformat()
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
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
                                    "ISO 27001:2013 A.13.2.1"
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{instanceArn}/attack-surface-ec2-open-{serviceName}-check",
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
                            "Title": f"[AttackSurface.EC2.{checkIdNumber}] EC2 Instances should not have a publicly reachable {serviceName} service",
                            "Description": f"EC2 instance {instanceId} is not publicly reachable on port {portNumber} which corresponds to the {serviceName} service due to {serviceStateReason}. Instances and their respective Security Groups should still be reviewed for minimum necessary access.",
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
                                            "SubnetId": subnetId,
                                            "LaunchedAt": parse(instanceLaunchedAt).isoformat()
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
                                    "ISO 27001:2013 A.13.2.1"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding