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

import nmap3
import datetime
from check_register import CheckRegister
from dateutil.parser import parse

registry = CheckRegister()

# Instantiate a NMAP scanner for TCP scans to define ports
nmap = nmap3.NmapScanTechniques()

def ec2_paginate(cache, session):
    ec2 = session.client("ec2")
    
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

def describe_load_balancers(cache, session):
    elbv2 = session.client("elbv2")

    # loop through ELBv2 load balancers
    response = cache.get("describe_load_balancers")
    if response:
        return response
    cache["describe_load_balancers"] = elbv2.describe_load_balancers()
    return cache["describe_load_balancers"]

def describe_clbs(cache, session):
    elb = session.client("elb")

    # loop through ELB load balancers
    response = cache.get("describe_load_balancers")
    if response:
        return response
    cache["describe_load_balancers"] = elb.describe_load_balancers()
    return cache["describe_load_balancers"]

def cloudfront_paginate(cache, session):
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

def get_public_hosted_zones(cache, session):
    route53 = session.client("route53")

    zones = []
    response = cache.get("get_hosted_zones")
    if response:
        return response
    paginator = route53.get_paginator('list_hosted_zones')
    if paginator:
        for page in paginator.paginate():
            for hz in page["HostedZones"]:
                if str(hz["Config"]["PrivateZone"]) == "False":
                    zones.append(hz)
                else:
                    continue
        cache["get_hosted_zones"] = zones
        return cache["get_hosted_zones"]

# This function performs the actual NMAP Scan
def scan_host(host_ip, host_name, asset_type):
    try:
        results = nmap.nmap_tcp_scan(
            host_ip,
            # FTP, SSH, TelNet, SMTP, HTTP, POP3, NetBIOS, SMB, RDP, MSSQL, MySQL/MariaDB, NFS, Docker, Oracle, PostgreSQL, 
            # Kibana, VMWare, Proxy, Splunk, K8s, Redis, Kafka, Mongo, Rabbit/AmazonMQ, SparkUI
            args="-Pn -p 21,22,23,25,80,110,139,445,3389,1433,3306,2049,2375,1521,5432,5601,8182,8080,8089,10250,6379,9092,27017,5672,4040"
        )

        print(f"Scanning {asset_type} {host_name} on {host_ip}")
        return results
    except KeyError:
        results = None

@registry.register_check("ec2")
def ec2_attack_surface_open_tcp_port_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AttackSurface.EC2.{checkIdNumber}] EC2 Instances should not be publicly reachable on {serviceName}"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # Paginate the iterator object from Cache
    for i in ec2_paginate(cache, session):
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
            scanner = scan_host(hostIp, instanceId, "EC2 Instance")
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
                    elif portNumber == 5672:
                        serviceName = 'RABBITMQ'
                    elif portNumber == 4040:
                        serviceName = 'SPARK-WEBUI'
                    else:
                        try:
                            serviceName = str(p["service"]["name"]).upper()
                        except KeyError:
                            serviceName = "Unknown"
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
                                    "Text": "EC2 Instances should only have the minimum necessary ports open to achieve their purposes, allow traffic from authorized sources, and use other defense-in-depth and hardening strategies. For a basic view on traffic authorization into your instances refer to the Authorize inbound traffic for your Linux instances section of the Amazon Elastic Compute Cloud User Guide",
                                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Compute",
                                "AssetService": "Amazon EC2",
                                "AssetType": "EC2 Instance"
                            },
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
                                    "NIST CSF V1.1 PR.AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-17",
                                    "NIST SP 800-53 Rev. 4 AC-19",
                                    "NIST SP 800-53 Rev. 4 AC-20",
                                    "NIST SP 800-53 Rev. 4 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
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
                            "Title": f"[AttackSurface.EC2.{checkIdNumber}] EC2 Instances should not be publicly reachable on {serviceName}",
                            "Description": f"EC2 instance {instanceId} is not publicly reachable on port {portNumber} which corresponds to the {serviceName} service due to {serviceStateReason}. Instances and their respective Security Groups should still be reviewed for minimum necessary access.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EC2 Instances should only have the minimum necessary ports open to achieve their purposes, allow traffic from authorized sources, and use other defense-in-depth and hardening strategies. For a basic view on traffic authorization into your instances refer to the Authorize inbound traffic for your Linux instances section of the Amazon Elastic Compute Cloud User Guide",
                                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Compute",
                                "AssetService": "Amazon EC2",
                                "AssetType": "EC2 Instance"
                            },
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
                                    "NIST CSF V1.1 PR.AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-17",
                                    "NIST SP 800-53 Rev. 4 AC-19",
                                    "NIST SP 800-53 Rev. 4 AC-20",
                                    "NIST SP 800-53 Rev. 4 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
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

@registry.register_check("elbv2")
def elbv2_attack_surface_open_tcp_port_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AttackSurface.ELBv2.{checkIdNumber}] Application Load Balancers should not be publicly reachable on {serviceName}"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # Loop ELBs and select the public ALBs
    for lb in describe_load_balancers(cache, session)["LoadBalancers"]:
        elbv2Arn = str(lb["LoadBalancerArn"])
        elbv2Name = str(lb["LoadBalancerName"])
        elbv2DnsName = str(lb["DNSName"])
        elbv2LbType = str(lb["Type"])
        elbv2Scheme = str(lb["Scheme"])
        elbv2VpcId = str(lb["VpcId"])
        elbv2IpAddressType = str(lb["IpAddressType"])
        if (elbv2Scheme == 'internet-facing' and elbv2LbType == 'application'):
            scanner = scan_host(elbv2DnsName, elbv2Name, "Application load balancer")
            # NoneType returned on KeyError due to Nmap errors
            if scanner == None:
                continue
            else:
                # Pull out the IP resolution of the DNS Name
                keys = scanner.keys()
                hostIp = (list(keys)[0])
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
                    elif portNumber == 5672:
                        serviceName = 'RABBITMQ'
                    elif portNumber == 4040:
                        serviceName = 'SPARK-WEBUI'
                    else:
                        try:
                            serviceName = str(p["service"]["name"]).upper()
                        except KeyError:
                            serviceName = "Unknown"
                    serviceStateReason = str(p["reason"])
                    serviceState = str(p["state"])
                    # This is a failing check
                    if serviceState == "open":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{elbv2Arn}/attack-surface-elbv2-open-{serviceName}-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
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
                            "Title": f"[AttackSurface.ELBv2.{checkIdNumber}] Application Load Balancers should not be publicly reachable on {serviceName}",
                            "Description": f"Application load balancer {elbv2Name} is publicly reachable on port {portNumber} which corresponds to the {serviceName} service. When Services are successfully fingerprinted by the ElectricEye Attack Surface Management Auditor it means the instance is Public, has an open Secuirty Group rule, and a running service on the host which adversaries can also see. Refer to the remediation insturctions for an example of a way to secure EC2 instances.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ALB security group reccomendations refer to the Security groups for your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html#security-group-recommended-rules"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Networking",
                                "AssetService": "AWS Elastic Load Balancer V2",
                                "AssetType": "Application Load Balancer"
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
                                            "IpAddressType": elbv2IpAddressType,
                                            "Scheme": elbv2Scheme,
                                            "Type": elbv2LbType,
                                            "VpcId": elbv2VpcId
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-17",
                                    "NIST SP 800-53 Rev. 4 AC-19",
                                    "NIST SP 800-53 Rev. 4 AC-20",
                                    "NIST SP 800-53 Rev. 4 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
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
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{elbv2Arn}/attack-surface-elbv2-open-{serviceName}-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
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
                            "Title": f"[AttackSurface.ELBv2.{checkIdNumber}] Application Load Balancers should not be publicly reachable on {serviceName}",
                            "Description": f"Application load balancer {elbv2Name} is not publicly reachable on port {portNumber} which corresponds to the {serviceName} service due to {serviceStateReason}. ALBs and their respective Security Groups should still be reviewed for minimum necessary access.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ALB security group reccomendations refer to the Security groups for your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html#security-group-recommended-rules"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Networking",
                                "AssetService": "AWS Elastic Load Balancer V2",
                                "AssetType": "Application Load Balancer"
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
                                            "IpAddressType": elbv2IpAddressType,
                                            "Scheme": elbv2Scheme,
                                            "Type": elbv2LbType,
                                            "VpcId": elbv2VpcId
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-17",
                                    "NIST SP 800-53 Rev. 4 AC-19",
                                    "NIST SP 800-53 Rev. 4 AC-20",
                                    "NIST SP 800-53 Rev. 4 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
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
            continue

@registry.register_check("elb")
def elb_attack_surface_open_tcp_port_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AttackSurface.ELB.{checkIdNumber}] Classic Load Balancers should not be publicly reachable on {serviceName}"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_clbs(cache, session)["LoadBalancerDescriptions"]:
        clbName = str(lb["LoadBalancerName"])
        clbArn = f"arn:{awsPartition}:elasticloadbalancing:{awsRegion}:{awsAccountId}:loadbalancer/{clbName}"
        dnsName = str(lb["DNSName"])
        lbSgs = lb["SecurityGroups"]
        lbSubnets = lb["Subnets"]
        lbAzs = lb["AvailabilityZones"]
        lbVpc = lb["VPCId"]
        clbScheme = str(lb["Scheme"])
        if clbScheme == 'internet-facing':
            scanner = scan_host(dnsName, clbName)
            # NoneType returned on KeyError due to Nmap errors
            if scanner == None:
                continue
            else:
                # Pull out the IP resolution of the DNS Name
                keys = scanner.keys()
                hostIp = (list(keys)[0])
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
                    elif portNumber == 5672:
                        serviceName = 'RABBITMQ'
                    elif portNumber == 4040:
                        serviceName = 'SPARK-WEBUI'
                    else:
                        try:
                            serviceName = str(p["service"]["name"]).upper()
                        except KeyError:
                            serviceName = "Unknown"
                    serviceStateReason = str(p["reason"])
                    serviceState = str(p["state"])
                    # This is a failing check
                    if serviceState == "open":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{clbArn}/attack-surface-elb-open-{serviceName}-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": clbArn,
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
                            "Title": f"[AttackSurface.ELB.{checkIdNumber}] Classic Load Balancers should not be publicly reachable on {serviceName}",
                            "Description": f"Classic load balancer {clbName} is publicly reachable on port {portNumber} which corresponds to the {serviceName} service. When Services are successfully fingerprinted by the ElectricEye Attack Surface Management Auditor it means the instance is Public, has an open Secuirty Group rule, and a running service on the host which adversaries can also see. Refer to the remediation insturctions for an example of a way to secure EC2 instances.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ALB security group reccomendations refer to the Security groups for your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html#security-group-recommended-rules"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Networking",
                                "AssetService": "AWS Elastic Load Balancer",
                                "AssetType": "Classic Load Balancer"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsElbLoadBalancer",
                                    "Id": clbArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElbLoadBalancer": {
                                            "DnsName": dnsName,
                                            "Scheme": clbScheme,
                                            "SecurityGroups": lbSgs,
                                            "Subnets": lbSubnets,
                                            "VpcId": lbVpc,
                                            "AvailabilityZones": lbAzs,
                                            "LoadBalancerName": clbName
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-17",
                                    "NIST SP 800-53 Rev. 4 AC-19",
                                    "NIST SP 800-53 Rev. 4 AC-20",
                                    "NIST SP 800-53 Rev. 4 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
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
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{clbArn}/attack-surface-elb-open-{serviceName}-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": clbArn,
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
                            "Title": f"[AttackSurface.ELB.{checkIdNumber}] Classic Load Balancers should not be publicly reachable on {serviceName}",
                            "Description": f"Classic load balancer {clbName} is not publicly reachable on port {portNumber} which corresponds to the {serviceName} service due to {serviceStateReason}. CLBs and their respective Security Groups should still be reviewed for minimum necessary access.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ALB security group reccomendations refer to the Security groups for your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html#security-group-recommended-rules"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Networking",
                                "AssetService": "AWS Elastic Load Balancer",
                                "AssetType": "Classic Load Balancer"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsElbLoadBalancer",
                                    "Id": clbArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElbLoadBalancer": {
                                            "DnsName": dnsName,
                                            "Scheme": clbScheme,
                                            "SecurityGroups": lbSgs,
                                            "Subnets": lbSubnets,
                                            "VpcId": lbVpc,
                                            "AvailabilityZones": lbAzs,
                                            "LoadBalancerName": clbName
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-17",
                                    "NIST SP 800-53 Rev. 4 AC-19",
                                    "NIST SP 800-53 Rev. 4 AC-20",
                                    "NIST SP 800-53 Rev. 4 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
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
            continue

@registry.register_check("ec2")
def eip_attack_surface_open_tcp_port_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AttackSurface.EIP.{checkIdNumber}] Elastic IPs should not advertise publicly reachable {serviceName} services"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # Gather all EIPs
    ec2 = session.client("ec2")
    for x in ec2.describe_addresses()["Addresses"]:
        publicIp = x["PublicIp"]
        allocationId = x["AllocationId"]
        eipArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:eip-allocation/{allocationId}"
        privateIpAddress = x["PrivateIpAddress"]
        # Logic time
        scanner = scan_host(publicIp, allocationId, "Elastic IP")
        # NoneType returned on KeyError due to Nmap errors
        if scanner == None:
            continue
        else:
            # Loop the results of the scan - starting with Open Ports which require a combination of
            # a Public Instance, an open SG rule, and a running service/server on the host itself
            # use enumerate and a fixed offset to product the Check Title ID number
            for index, p in enumerate(scanner[publicIp]["ports"]):
                # Parse out the Protocol, Port, Service, and State/State Reason from NMAP Results
                checkIdNumber = str(int(index + 1))
                portNumber = int(p["portid"])
                if portNumber == 8089:
                    serviceName = 'SPLUNKD'
                elif portNumber == 10250:
                    serviceName = 'KUBERNETES-API'
                elif portNumber == 5672:
                    serviceName = 'RABBITMQ'
                elif portNumber == 4040:
                    serviceName = 'SPARK-WEBUI'
                else:
                    try:
                        serviceName = str(p["service"]["name"]).upper()
                    except KeyError:
                        serviceName = "Unknown"
                serviceStateReason = str(p["reason"])
                serviceState = str(p["state"])
                # This is a failing check
                if serviceState == "open":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{eipArn}/attack-surface-eip-open-{serviceName}-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": eipArn,
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
                        "Title": f"[AttackSurface.EIP.{checkIdNumber}] Elastic IPs should not advertise publicly reachable {serviceName} services",
                        "Description": f"Elastic IP address {publicIp} is publicly reachable on port {portNumber} which corresponds to the {serviceName} service. When Services are successfully fingerprinted by the ElectricEye Attack Surface Management Auditor it means the instance is Public, has an open Secuirty Group rule, and a running service on the host which adversaries can also see. Refer to the remediation insturctions for an example of a way to secure EC2 instances.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "EC2 Instances should only have the minimum necessary ports open to achieve their purposes, allow traffic from authorized sources, and use other defense-in-depth and hardening strategies. For a basic view on traffic authorization into your instances refer to the Authorize inbound traffic for your Linux instances section of the Amazon Elastic Compute Cloud User Guide",
                                "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Networking",
                            "AssetService": "Amazon EC2",
                            "AssetType": "Elastic IP"
                        },
                        "Resources": [
                            {
                                "Type": "AwsEc2Eip",
                                "Id": eipArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Eip": {
                                        "PublicIp": publicIp,
                                        "AllocationId": allocationId,
                                        "PrivateIpAddress": privateIpAddress
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.AC-3",
                                "NIST SP 800-53 Rev. 4 AC-1",
                                "NIST SP 800-53 Rev. 4 AC-17",
                                "NIST SP 800-53 Rev. 4 AC-19",
                                "NIST SP 800-53 Rev. 4 AC-20",
                                "NIST SP 800-53 Rev. 4 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
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
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{eipArn}/attack-surface-eip-open-{serviceName}-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": eipArn,
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
                        "Title": f"[AttackSurface.EIP.{checkIdNumber}] Elastic IPs should not advertise publicly reachable {serviceName} services",
                        "Description": f"Elastic IP address {publicIp} is not publicly reachable on port {portNumber} which corresponds to the {serviceName} service due to {serviceStateReason}. EIPs and their respective Security Groups should still be reviewed for minimum necessary access.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "EC2 Instances should only have the minimum necessary ports open to achieve their purposes, allow traffic from authorized sources, and use other defense-in-depth and hardening strategies. For a basic view on traffic authorization into your instances refer to the Authorize inbound traffic for your Linux instances section of the Amazon Elastic Compute Cloud User Guide",
                                "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Networking",
                            "AssetService": "Amazon EC2",
                            "AssetType": "Elastic IP"
                        },
                        "Resources": [
                            {
                                "Type": "AwsEc2Eip",
                                "Id": eipArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Eip": {
                                        "PublicIp": publicIp,
                                        "AllocationId": allocationId,
                                        "PrivateIpAddress": privateIpAddress
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.AC-3",
                                "NIST SP 800-53 Rev. 4 AC-1",
                                "NIST SP 800-53 Rev. 4 AC-17",
                                "NIST SP 800-53 Rev. 4 AC-19",
                                "NIST SP 800-53 Rev. 4 AC-20",
                                "NIST SP 800-53 Rev. 4 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
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

@registry.register_check("cloudfront")
def cloudfront_attack_surface_open_tcp_port_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AttackSurface.Cloudfront.{checkIdNumber}] Cloudfront Distributions should not be publicly reachable on {serviceName}"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in cloudfront_paginate(cache, session):
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Logic time
        scanner = scan_host(domainName, distributionId, "CloudFront Distribution")
        # NoneType returned on KeyError due to Nmap errors
        if scanner == None:
            continue
        else:
            # Pull out the IP resolution of the DNS Name
            keys = scanner.keys()
            hostIp = (list(keys)[0])
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
                elif portNumber == 5672:
                    serviceName = 'RABBITMQ'
                elif portNumber == 4040:
                    serviceName = 'SPARK-WEBUI'
                else:
                    try:
                        serviceName = str(p["service"]["name"]).upper()
                    except KeyError:
                        serviceName = "Unknown"
                serviceStateReason = str(p["reason"])
                serviceState = str(p["state"])
                # This is a failing check
                if serviceState == "open":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{distributionArn}/attack-surface-cfront-open-{serviceName}-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": distributionArn,
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
                        "Title": f"[AttackSurface.Cloudfront.{checkIdNumber}] Cloudfront Distributions should not be publicly reachable on {serviceName}",
                        "Description": f"CloudFront Distribution {distributionId} is publicly reachable on port {portNumber} which corresponds to the {serviceName} service. When Services are successfully fingerprinted by the ElectricEye Attack Surface Management Auditor it means the instance is Public, has an open Secuirty Group rule, and a running service on the host which adversaries can also see. Refer to the remediation insturctions for an example of a way to secure EC2 instances.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information about protecting Origins behind CloudFront distros refer to the Data protection in Amazon CloudFront section of the Amazon CloudFront Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/data-protection-summary.html"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Networking",
                            "AssetService": "Amazon CloudFront",
                            "AssetType": "Distribution"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": domainName,
                                        "Status": distStatus
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.AC-3",
                                "NIST SP 800-53 Rev. 4 AC-1",
                                "NIST SP 800-53 Rev. 4 AC-17",
                                "NIST SP 800-53 Rev. 4 AC-19",
                                "NIST SP 800-53 Rev. 4 AC-20",
                                "NIST SP 800-53 Rev. 4 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
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
                # this is a passing check
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{distributionArn}/attack-surface-cfront-open-{serviceName}-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": distributionArn,
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
                        "Title": f"[AttackSurface.Cloudfront.{checkIdNumber}] Cloudfront Distributions should not be publicly reachable on {serviceName}",
                        "Description": f"CloudFront Distribution {distributionId} is not publicly reachable on port {portNumber} which corresponds to the {serviceName} service due to {serviceStateReason}. Distributions and their respective Security Groups and Origins should still be reviewed for minimum necessary access.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information about protecting Origins behind CloudFront distros refer to the Data protection in Amazon CloudFront section of the Amazon CloudFront Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/data-protection-summary.html"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Networking",
                            "AssetService": "Amazon CloudFront",
                            "AssetType": "Distribution"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": domainName,
                                        "Status": distStatus
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.AC-3",
                                "NIST SP 800-53 Rev. 4 AC-1",
                                "NIST SP 800-53 Rev. 4 AC-17",
                                "NIST SP 800-53 Rev. 4 AC-19",
                                "NIST SP 800-53 Rev. 4 AC-20",
                                "NIST SP 800-53 Rev. 4 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
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

@registry.register_check("cloudfront")
def route53_public_hz_attack_surface_open_tcp_port_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AttackSurface.Route53.{checkIdNumber}] Route53 Public Hosted Zones A Records should not be publicly reachable on {serviceName}"""
    route53 = session.client("route53")

    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for zone in get_public_hosted_zones(cache, session):
        hzId = zone["Id"]
        hzName = zone["Name"]
        hzArn = f"arn:aws:route53:::hostedzone/{hzName}"
        # Get the A Records
        for record in route53.list_resource_record_sets(HostedZoneId=hzId)["ResourceRecordSets"]:
            # skip non "A" Records - "A" will also pick up on Alias records to LBs, etc.
            if str(record["Type"]) != "A":
                continue
            else:
                resourceRecord = str(record["Name"])
                # Logic time
                scanner = scan_host(resourceRecord, hzName, "Route53 Public Hosted Zone A Record")
                # NoneType returned on KeyError due to Nmap errors
                if scanner == None:
                    continue
                else:
                    # Pull out the IP resolution of the DNS Name
                    keys = scanner.keys()
                    hostIp = (list(keys)[0])
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
                        elif portNumber == 5672:
                            serviceName = 'RABBITMQ'
                        elif portNumber == 4040:
                            serviceName = 'SPARK-WEBUI'
                        else:
                            try:
                                serviceName = str(p["service"]["name"]).upper()
                            except KeyError:
                                serviceName = "Unknown"
                        serviceStateReason = str(p["reason"])
                        serviceState = str(p["state"])
                        # This is a failing check
                        if serviceState == "open":
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": f"{hzArn}/{resourceRecord}/attack-surface-cfront-open-{serviceName}-check",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": f"{hzArn}/{resourceRecord}",
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
                                "Title": f"[AttackSurface.Route53.{checkIdNumber}] Route53 Public Hosted Zones A Records should not be publicly reachable on {serviceName}",
                                "Description": f"Route53 Hosted Zone {hzId} named {hzName} on A Record {resourceRecord} is publicly reachable on port {portNumber} which corresponds to the {serviceName} service. When Services are successfully fingerprinted by the ElectricEye Attack Surface Management Auditor it means the instance is Public, has an open Secuirty Group rule, and a running service on the host which adversaries can also see. Refer to the remediation insturctions for an example of a way to secure EC2 instances.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For information about protecting Origins behind CloudFront distros refer to the Data protection in Amazon CloudFront section of the Amazon CloudFront Developer Guide",
                                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/data-protection-summary.html"
                                    }
                                },
                                "ProductFields": {
                                    "ProductName": "ElectricEye",
                                    "Provider": "AWS",
                                    "AssetClass": "Networking",
                                    "AssetService": "Amazon Route53",
                                    "AssetType": "Route53 Hosted Zone Resource Record"
                                },
                                "Resources": [
                                    {
                                        "Type": "AwsRoute53HostedZoneResourceRecord",
                                        "Id": f"{hzArn}/{resourceRecord}",
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "Other": {
                                                "Id": hzId,
                                                "Name": hzName,
                                                "ResourceRecordName": resourceRecord,
                                                "ResourceRecordType": "A",
                                                "PrivateZone": "False"
                                            }
                                        }
                                    }
                                ],
                                "Compliance": {
                                    "Status": "FAILED",
                                    "RelatedRequirements": [
                                        "NIST CSF V1.1 PR.AC-3",
                                        "NIST SP 800-53 Rev. 4 AC-1",
                                        "NIST SP 800-53 Rev. 4 AC-17",
                                        "NIST SP 800-53 Rev. 4 AC-19",
                                        "NIST SP 800-53 Rev. 4 AC-20",
                                        "NIST SP 800-53 Rev. 4 SC-15",
                                        "AICPA TSC CC6.6",
                                        "ISO 27001:2013 A.6.2.1",
                                        "ISO 27001:2013 A.6.2.2",
                                        "ISO 27001:2013 A.11.2.6",
                                        "ISO 27001:2013 A.13.1.1",
                                        "ISO 27001:2013 A.13.2.1",
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
                        # this is a passing check
                        else:
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": f"{hzArn}/{resourceRecord}/attack-surface-cfront-open-{serviceName}-check",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": f"{hzArn}/{resourceRecord}",
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
                                "Title": f"[AttackSurface.Route53.{checkIdNumber}] Route53 Public Hosted Zones A Records should not be publicly reachable on {serviceName}",
                                "Description": f"Route53 Hosted Zone {hzId} named {hzName} on A Record {resourceRecord} is not publicly reachable on port {portNumber} which corresponds to the {serviceName} service due to {serviceStateReason}. When Services are successfully fingerprinted by the ElectricEye Attack Surface Management Auditor it means the instance is Public, has an open Secuirty Group rule, and a running service on the host which adversaries can also see. Refer to the remediation insturctions for an example of a way to secure EC2 instances.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For information about protecting Origins behind CloudFront distros refer to the Data protection in Amazon CloudFront section of the Amazon CloudFront Developer Guide",
                                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/data-protection-summary.html"
                                    }
                                },
                                "ProductFields": {
                                    "ProductName": "ElectricEye",
                                    "Provider": "AWS",
                                    "AssetClass": "Networking",
                                    "AssetService": "Amazon Route53",
                                    "AssetType": "Route53 Hosted Zone Resource Record"
                                },
                                "Resources": [
                                    {
                                        "Type": "AwsRoute53HostedZoneResourceRecord",
                                        "Id": f"{hzArn}/{resourceRecord}",
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "Other": {
                                                "Id": hzId,
                                                "Name": hzName,
                                                "ResourceRecordName": resourceRecord,
                                                "ResourceRecordType": "A",
                                                "PrivateZone": "False"
                                            }
                                        }
                                    }
                                ],
                                "Compliance": {
                                    "Status": "PASSED",
                                    "RelatedRequirements": [
                                        "NIST CSF V1.1 PR.AC-3",
                                        "NIST SP 800-53 Rev. 4 AC-1",
                                        "NIST SP 800-53 Rev. 4 AC-17",
                                        "NIST SP 800-53 Rev. 4 AC-19",
                                        "NIST SP 800-53 Rev. 4 AC-20",
                                        "NIST SP 800-53 Rev. 4 SC-15",
                                        "AICPA TSC CC6.6",
                                        "ISO 27001:2013 A.6.2.1",
                                        "ISO 27001:2013 A.6.2.2",
                                        "ISO 27001:2013 A.11.2.6",
                                        "ISO 27001:2013 A.13.1.1",
                                        "ISO 27001:2013 A.13.2.1",
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

# TODO: Global Accelerator ?!