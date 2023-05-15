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

import os
import oci
from oci.config import validate_config
import nmap3
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

# Instantiate a NMAP scanner for TCP scans to define ports
nmap = nmap3.NmapScanTechniques()

def process_response(responseObject):
    """
    Receives an OCI Python SDK `Response` type (differs by service) and returns a JSON object
    """

    payload = json.loads(
        str(
            responseObject
        )
    )

    return payload

def get_oci_compute_instances(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_oci_compute_instances")
    if response:
        return response

    # Create & Validate OCI Creds - do this after cache check to avoid doing it a lot
    config = {
        "tenancy": ociTenancyId,
        "user": ociUserId,
        "region": ociRegionName,
        "fingerprint": ociUserApiKeyFingerprint,
        "key_file": os.environ["OCI_PEM_FILE_PATH"],
        
    }
    validate_config(config)

    instanceClient = oci.core.ComputeClient(config)

    instancesList = []

    for compartment in ociCompartments:
        listInstances = instanceClient.list_instances(compartment_id=compartment, lifecycle_state="RUNNING").data
        if not listInstances:
            return {}
        else:
            for instance in listInstances:
                processedInstance = process_response(instance)
                instancesList.append(processedInstance)

    cache["get_oci_compute_instances"] = instancesList
    return cache["get_oci_compute_instances"]

# Needed to get the Public IP of an Instance
def get_compute_instance_vnic(ociTenancyId, ociUserId, ociRegionName, ociUserApiKeyFingerprint, compartmentId, instanceId):
    """
    Helper function to retrieve the Virtual NIC & Network Security Group information for a Cloud Compute Instance.
    OCI requires you to call ListVnicAttachments, derive the VNC OCID, and use that to call the GetVnic ID in another
    client object. The response of GetVnic contains information on the public IP of an instance and the associated NSGs
    """

    # Create & Validate OCI Creds - do this after cache check to avoid doing it a lot
    config = {
        "tenancy": ociTenancyId,
        "user": ociUserId,
        "region": ociRegionName,
        "fingerprint": ociUserApiKeyFingerprint,
        "key_file": os.environ["OCI_PEM_FILE_PATH"],
        
    }
    validate_config(config)

    instanceClient = oci.core.ComputeClient(config)
    vncClient = oci.core.VirtualNetworkClient(config)

    vnics = instanceClient.list_vnic_attachments(compartment_id=compartmentId, instance_id=instanceId).data
    vnicId = process_response(vnics)[0]["vnic_id"]
    vnicData = vncClient.get_vnic(vnic_id=vnicId).data

    return process_response(vnicData)

# This function performs the actual NMAP Scan
def scan_host(hostIp, assetName, assetComponent):
    try:
        results = nmap.nmap_tcp_scan(
            hostIp,
            # FTP, SSH, TelNet, SMTP, HTTP, POP3, NetBIOS, SMB, RDP, MSSQL, MySQL/MariaDB, NFS, Docker, Oracle, PostgreSQL, 
            # Kibana, VMWare, Proxy, Splunk, K8s, Redis, Kafka, Mongo, Rabbit/AmazonMQ, SparkUI
            args="-Pn -p 21,22,23,25,80,110,139,445,3389,1433,3306,2049,2375,1521,5432,5601,8182,8080,8089,10250,6379,9092,27017,5672,4040"
        )

        print(f"Scanning {assetComponent} {assetName} on {hostIp}")
        return results
    except KeyError:
        results = None

@registry.register_check("oci.computeinstances")
def oci_compute_attack_surface_open_tcp_port_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [AttackSurface.OCI.ComputeInstance.{checkIdNumber}] Cloud Compute instances should not be publicly reachable on {serviceName}    
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for instance in get_oci_compute_instances(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(instance,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = instance["id"]
        instanceName = instance["display_name"]
        compartmentId = instance["compartment_id"]
        imageId = instance["image_id"]
        shape = instance["shape"]
        lifecycleState = instance["lifecycle_state"]
        # Get the VNIC info
        instanceVnic = get_compute_instance_vnic(ociTenancyId, ociUserId, ociRegionName, ociUserApiKeyFingerprint, compartmentId, instanceId)
        # Skip over instances that are not public
        pubIp = instanceVnic["public_ip"]
        if instanceVnic["public_ip"] is None:
            continue
        # Submit details to the scanner function
        scanner = scan_host(pubIp, instanceName, "OCI Cloud Compute instance")
        # NoneType returned on KeyError due to Nmap errors
        if scanner == None:
            continue
        else:
            # Loop the results of the scan - starting with Open Ports which require a combination of
            # a Public Instance, an open SG rule, and a running service/server on the host itself
            # use enumerate and a fixed offset to product the Check Title ID number
            for index, p in enumerate(scanner[pubIp]["ports"]):
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
                        "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-attack-surface-compute-instance-open-{serviceName}-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-attack-surface-compute-instance-open-{serviceName}-check",
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
                        "Title": f"[AttackSurface.OCI.ComputeInstance.{checkIdNumber}] Cloud Compute instances should not be publicly reachable on {serviceName}",
                        "Description": f"Oracle Cloud Compute instance {instanceName} in Compartment {compartmentId} in {ociRegionName} is publicly reachable on port {portNumber} which corresponds to the {serviceName} service. When Services are successfully fingerprinted by the ElectricEye Attack Surface Management Auditor it means the instance is public (mapped 'public_ip` in the associated vNIC), has an open Security List or Network Security Group, and a running service on the host which adversaries can also see. Refer to the remediation insturctions for an example of a way to secure OCI Cloud Compute instances.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "OCI Cloud Compute instances should only have the minimum necessary ports open to achieve their purposes, allow traffic from authorized sources, and use other defense-in-depth and hardening strategies. For a basic view on traffic authorization into your instances refer to the Public IP Addresses section of the Oracle Cloud Infrastructure Documentation for Networks.",
                                "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingpublicIPs.htm#Public_IP_Addresses"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "OCI",
                            "ProviderType": "CSP",
                            "ProviderAccountId": ociTenancyId,
                            "AssetRegion": ociRegionName,
                            "AssetDetails": assetB64,
                            "AssetClass": "Compute",
                            "AssetService": "Oracle Cloud Compute",
                            "AssetComponent": "Instance"
                        },
                        "Resources": [
                            {
                                "Type": "OciCloudComputeInstance",
                                "Id": instanceId,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "TenancyId": ociTenancyId,
                                        "CompartmentId": compartmentId,
                                        "Region": ociRegionName,
                                        "Name": instanceName,
                                        "Id": instanceId,
                                        "ImageId": imageId,
                                        "Shape": shape,
                                        "LifecycleState": lifecycleState
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
                        "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-attack-surface-compute-instance-open-{serviceName}-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-attack-surface-compute-instance-open-{serviceName}-check",
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
                        "Title": f"[AttackSurface.OCI.ComputeInstance.{checkIdNumber}] Cloud Compute instances should not be publicly reachable on {serviceName}",
                        "Description": f"Oracle Cloud Compute instance {instanceName} in Compartment {compartmentId} in {ociRegionName} is not publicly reachable on port {portNumber} which corresponds to the {serviceName} service due to {serviceStateReason}. OCI Cloud Compute instances and their respective Security Lists and/or Network Security Groups should still be reviewed for minimum necessary access.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "OCI Cloud Compute instances should only have the minimum necessary ports open to achieve their purposes, allow traffic from authorized sources, and use other defense-in-depth and hardening strategies. For a basic view on traffic authorization into your instances refer to the Public IP Addresses section of the Oracle Cloud Infrastructure Documentation for Networks.",
                                "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingpublicIPs.htm#Public_IP_Addresses"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "OCI",
                            "ProviderType": "CSP",
                            "ProviderAccountId": ociTenancyId,
                            "AssetRegion": ociRegionName,
                            "AssetDetails": assetB64,
                            "AssetClass": "Compute",
                            "AssetService": "Oracle Cloud Compute",
                            "AssetComponent": "Instance"
                        },
                        "Resources": [
                            {
                                "Type": "OciCloudComputeInstance",
                                "Id": instanceId,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "TenancyId": ociTenancyId,
                                        "CompartmentId": compartmentId,
                                        "Region": ociRegionName,
                                        "Name": instanceName,
                                        "Id": instanceId,
                                        "ImageId": imageId,
                                        "Shape": shape,
                                        "LifecycleState": lifecycleState
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


# END ??