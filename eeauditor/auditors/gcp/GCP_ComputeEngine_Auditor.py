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
import googleapiclient.discovery

registry = CheckRegister()

def get_compute_engine_instances(cache: dict, gcpProjectId: str):
    '''
    AggregatedList result provides Zone information as well as every single Instance in a Project
    '''
    if cache:
        return cache
    
    results = []

    compute = googleapiclient.discovery.build('compute', 'v1')

    aggResult = compute.instances().aggregatedList(project=gcpProjectId).execute()

    # Write all Zones to list
    zoneList = []
    for zone in aggResult["items"].keys():
        zoneList.append(zone)

    # If the Zone has a top level key of "warning" it does not contain entries
    for z in zoneList:
        for agg in aggResult["items"][z]:
            if agg == 'warning':
                continue
            # reloop the list except looking at instances - this is a normal List we can loop
            else:
                for i in aggResult["items"][z]["instances"]:
                    results.append(i)

    del aggResult
    del zoneList

    return results

@registry.register_check("gce")
def gce_instance_deletion_protection_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.1] Google Compute Engine VM instances should have deletion protection enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        if gce["deletionProtection"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-del-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-del-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.GCE.1] Google Compute Engine VM instances should have deletion protection enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} does not have deletion protection enabled. As part of your workload, there might be certain VM instances that are critical to running your application or services, such as an instance running a SQL server, a server used as a license manager, and so on. These VM instances might need to stay running indefinitely so you need a way to protect these VMs from being deleted. With Deletion Protection enabled, you have the guarantee that your VM instances cannot be accidentally deleted. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have deletion protection enabled refer to the Prevent accidental VM deletion section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/docs/instances/preventing-accidental-vm-deletion",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF ID.BE-5",
                        "NIST CSF PR.PT-5",
                        "NIST SP 800-53 CP-2",
                        "NIST SP 800-53 CP-11",
                        "NIST SP 800-53 SA-13",
                        "NIST SP 800-53 SA14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding    
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-del-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-del-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.GCE.1] Google Compute Engine VM instances should have deletion protection enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} has deletion protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have deletion protection enabled refer to the Prevent accidental VM deletion section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/docs/instances/preventing-accidental-vm-deletion",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF ID.BE-5",
                        "NIST CSF PR.PT-5",
                        "NIST SP 800-53 CP-2",
                        "NIST SP 800-53 CP-11",
                        "NIST SP 800-53 SA-13",
                        "NIST SP 800-53 SA14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("gce")
def gce_instance_ip_forwarding_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.2] Google Compute Engine VM instances should not have IP forwarding enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        if gce["canIpForward"] is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-ip-forward-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-ip-forward-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.GCE.2] Google Compute Engine VM instances should not have IP forwarding enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} allows IP forwarding. When the IP Forwarding feature is enabled the instance's network interface (NIC) acts as a router and can receive traffic addressed to other destinations. IP forwarding is rarely required, unless the VM instance is used as a network virtual appliance, thus each VM instance should be reviewed in order to decide whether the IP forwarding is really needed for the verified instance. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should not have IP forwarding enabled refer to the Enable IP forwarding for instances section of the GCP Virtual Private Cloud guide.",
                        "Url": "https://cloud.google.com/vpc/docs/using-routes#canipforward",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
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
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-ip-forward-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-ip-forward-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.GCE.2] Google Compute Engine VM instances should not have IP forwarding enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} does not allow IP forwarding.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should not have IP forwarding enabled refer to the Enable IP forwarding for instances section of the GCP Virtual Private Cloud guide.",
                        "Url": "https://cloud.google.com/vpc/docs/using-routes#canipforward",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
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

@registry.register_check("gce")
def gce_instance_auto_restart_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.3] Google Compute Engine VM instances should have automatic restart enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        if gce["scheduling"]["automaticRestart"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-instance-restart-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-instance-restart-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[GCP.GCE.3] Google Compute Engine VM instances should have automatic restart enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} does not have automatic restarts enabled. Enabling GCP VM instance Auto Restart increases availability by automatically restarting an instance in the event of a failure or error. This reduces downtime, ensures application accessibility, and improves overall system reliability.. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have automatic restarts enabled refer to the Set host maintenance policy of a VM section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/docs/instances/setting-vm-host-options",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.MA-1",
                        "NIST SP 800-53 MA-2",
                        "NIST SP 800-53 MA-3",
                        "NIST SP 800-53 MA-5",
                        "NIST SP 800-53 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-instance-restart-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-instance-restart-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.GCE.3] Google Compute Engine VM instances should have automatic restart enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} has automatic restarts enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have automatic restarts enabled refer to the Set host maintenance policy of a VM section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/docs/instances/setting-vm-host-options",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "Passed",
                    "RelatedRequirements": [
                        "NIST CSF PR.MA-1",
                        "NIST SP 800-53 MA-2",
                        "NIST SP 800-53 MA-3",
                        "NIST SP 800-53 MA-5",
                        "NIST SP 800-53 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("gce")
def gce_instance_secure_boot_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.4] Google Compute Engine VM instances should have Secure Boot enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        if gce["shieldedInstanceConfig"]["enableVtpm"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-secure-boot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-secure-boot-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[GCP.GCE.4] Google Compute Engine VM instances should have Secure Boot enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} does not have Secure Boot enabled. Secure Boot is a feature that ensures the integrity of the boot process by verifying the digital signature of the boot loader and the kernel. If Secure Boot is not enabled, the boot process may be susceptible to malware or unauthorized modifications that could compromise the security of the instance. Without Secure Boot malware may modify the boot loader or kernel to gain unauthorized access or otherwise interfere with the instance. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have Secure Boot enabled refer to the Secure Boot section of the GCP Virtual Private Cloud guide.",
                        "Url": "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#secure-boot",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-6",
                        "NIST SP 800-53 SC-16",
                        "NIST SP 800-53 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-secure-boot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-secure-boot-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.GCE.4] Google Compute Engine VM instances should have Secure Boot enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} has Secure Boot enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have Secure Boot enabled refer to the Secure Boot section of the GCP Virtual Private Cloud guide.",
                        "Url": "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#secure-boot",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-6",
                        "NIST SP 800-53 SC-16",
                        "NIST SP 800-53 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "NEW"
            }
            yield finding

@registry.register_check("gce")
def gce_instance_vtpm_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.5] Google Compute Engine VM instances should have Virtual Trusted Platform Module enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        if gce["shieldedInstanceConfig"]["enableVtpm"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-vtpm-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-vtpm-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[GCP.GCE.5] Google Compute Engine VM instances should have Virtual Trusted Platform Module enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} does not have Virtual Trusted Platform Module (vTPM) enabled. VTPM is a feature that provides hardware-level security by emulating a hardware TPM in a virtualized environment. If vTPM is not enabled, cryptographic keys and other sensitive data may be vulnerable to attacks that could compromise the security of the instance. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have VTPM enabled refer to the Virtual Trusted Platform Module (vTPM) section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#vtpm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-6",
                        "NIST SP 800-53 SC-16",
                        "NIST SP 800-53 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-vtpm-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-vtpm-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.GCE.5] Google Compute Engine VM instances should have Virtual Trusted Platform Module enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} has Virtual Trusted Platform Module (vTPM) enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have VTPM enabled refer to the Virtual Trusted Platform Module (vTPM) section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#vtpm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-6",
                        "NIST SP 800-53 SC-16",
                        "NIST SP 800-53 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("gce")
def gce_instance_integrity_mon_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.6] Google Compute Engine VM instances should have Integrity Monitoring enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        if gce["shieldedInstanceConfig"]["enableIntegrityMonitoring"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-integrity-mon-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-integrity-mon-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[GCP.GCE.6] Google Compute Engine VM instances should have Integrity Monitoring enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} does not have Integrity Monitoring enabled. Integrity Monitoring is a feature that provides continuous monitoring and detection of changes to the system and application files on the instance. If Integrity Monitoring is not enabled, changes to critical system files or applications may go undetected, allowing attackers to compromise the security of the instance. Without it, changes to critical system files or applications may go undetected, allowing attackers to install malware or tamper with the system. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have Integrity Monitoring enabled refer to the Integrity Monitoring section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#integrity-monitoring",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-6",
                        "NIST SP 800-53 SC-16",
                        "NIST SP 800-53 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-integrity-mon-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-integrity-mon-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.GCE.6] Google Compute Engine VM instances should have Integrity Monitoring enabled",
                "Description": f"Google Compute Engine instance {name} in {zone} has Integrity Monitoring enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have Integrity Monitoring enabled refer to the Integrity Monitoring section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#integrity-monitoring",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-6",
                        "NIST SP 800-53 SC-16",
                        "NIST SP 800-53 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("gce")
def gce_instance_siip_auto_update_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.7] Google Compute Engine VM instances should be configured to auto-update the Shielded Instance Integrity Auto-learn Policy
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        if gce["shieldedInstanceIntegrityPolicy"]["updateAutoLearnPolicy"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-integrity-update-auto-learn-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-integrity-update-auto-learn-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[GCP.GCE.7] Google Compute Engine VM instances should be configured to auto-update the Shielded Instance Integrity Auto-learn Policy",
                "Description": f"Google Compute Engine instance {name} in {zone} is not configured to auto-update the Shielded Instance Integrity Auto-learn Policy. The Shielded Instance Integrity Policy is a security feature in Google Cloud that helps protect VM instances against tampering and other unauthorized changes. This policy specifies a set of conditions that the instance must meet in order to be considered 'trusted', such as having a valid firmware, kernel, and boot loader, and not being modified since its last boot. It is recommended to set the Auto Learn Policy to Update for the Shielded Instance Integrity Policy on VM instances. This ensures that instances are always checked against the latest policy. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have instance integirty autolearning policy enabled refer to the Updating the integrity policy baseline section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/shielded-vm/docs/integrity-monitoring#updating-baseline",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-6",
                        "NIST SP 800-53 SC-16",
                        "NIST SP 800-53 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-integrity-update-auto-learn-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-integrity-update-auto-learn-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.GCE.7] Google Compute Engine VM instances should be configured to auto-update the Shielded Instance Integrity Auto-learn Policy",
                "Description": f"Google Compute Engine instance {name} in {zone} is configured to auto-update the Shielded Instance Integrity Auto-learn Policy.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have instance integirty autolearning policy enabled refer to the Updating the integrity policy baseline section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/shielded-vm/docs/integrity-monitoring#updating-baseline",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-6",
                        "NIST SP 800-53 SC-16",
                        "NIST SP 800-53 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("gce")
def gce_instance_confidential_compute_update_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.8] Google Compute Engine VM instances containing sensitive data or high-security workloads should enable Confidential Computing
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        if gce["confidentialInstanceConfig"]["enableConfidentialCompute"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-confidential-computing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-confidential-computing-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.GCE.8] Google Compute Engine VM instances containing sensitive data or high-security workloads should enable Confidential Computing",
                "Description": f"Google Compute Engine instance {name} in {zone} does not have Confidential Computing enabled. Confidential Computing is a computing paradigm that provides hardware-based security and encryption for data in use. It aims to protect data even from privileged users, such as system administrators or cloud providers, by isolating the data in a secure enclave that can only be accessed by authorized users or applications. If the application requires a high level of security and confidentiality for the data in use, then it may be appropriate to use Confidential VMs. For example, applications that handle sensitive financial or healthcare data may require Confidential VMs to protect against unauthorized access or data breaches. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have Confidential Computing enabled refer to the Confidential VM section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/confidential-vm/docs/about-cvm#confidential-vm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-confidential-computing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-confidential-computing-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.GCE.8] Google Compute Engine VM instances containing sensitive data or high-security workloads should enable Confidential Computing",
                "Description": f"Google Compute Engine instance {name} in {zone} has Confidential Computing enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should have Confidential Computing enabled refer to the Confidential VM section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/confidential-vm/docs/about-cvm#confidential-vm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
                            }
                        },
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

@registry.register_check("gce")
def gce_instance_serial_port_access_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.9] Google Compute Engine VM instances should not enabled serial port access
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    compute = googleapiclient.discovery.build('compute', 'v1')

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        # Check for Serial Port Access
        response = compute.instances().getSerialPortOutput(project=gcpProjectId, zone=zone, instance=id).execute()

        # Check if the serial port output indicates that Serial Console Access is enabled
        # Set an internal bool to go off to avoid writing multiple checks in the loops
        if 'Serial port 1 output' in response:
            if 'Serial console is listening' in response["Serial port 1 output"]:
                serialPortAccess = True
            else:
                serialPortAccess = False
        else:
            serialPortAccess = False
        # this is a failing check
        if serialPortAccess == True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-serial-port-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-serial-port-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[GCP.GCE.9] Google Compute Engine VM instances should not enabled serial port access",
                "Description": f"Google Compute Engine instance {name} in {zone} allows Serial Port access. Serial port access provides a direct, unencrypted connection to the console, which can be used to perform a wide range of attacks, such as injecting commands, modifying system files, or escalating privileges. Additionally, it may be difficult to monitor and audit serial port access, which can make it difficult to detect and respond to potential security incidents. It is generally recommended to disable serial port access for GCE VM instances unless it is specifically required for debugging or troubleshooting purposes, in which case it should be carefully controlled and monitored. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should not have Serial Port access enabled refer to the Enabling interactive access on the serial console section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console#enabling_interactive_access_on_the_serial_console",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
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
                "Id": f"{gcpProjectId}/{zone}/{id}/gce-instance-serial-port-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{id}/gce-instance-serial-port-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.GCE.9] Google Compute Engine VM instances should not enabled serial port access",
                "Description": f"Google Compute Engine instance {name} in {zone} does not allow Serial Port access.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your GCE VM instance should not have Serial Port access enabled refer to the Enabling interactive access on the serial console section of the GCP Compute Engine guide.",
                        "Url": "https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console#enabling_interactive_access_on_the_serial_console",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP"
                },
                "Resources": [
                    {
                        "Type": "GcpGceVmInstance",
                        "Id": f"{id}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "Id": id,
                                "Description": description,
                                "MachineType": machineType,
                                "CreatedAt": createdAt,
                                "LastStartedAt": lastStartedAt,
                                "Status": status
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

# OSLogon Check
@registry.register_check("gce")
def gce_instance_oslogon_access_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.10] Google Compute Engine VM instances should be configured to be accessed using OS Logon
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    compute = googleapiclient.discovery.build('compute', 'v1')

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        # Check for Serial Port Access
        response = compute.instances().getSerialPortOutput(project=gcpProjectId, zone=zone, instance=id).execute()

        if "enable-oslogin" in response["metadata"]["items"]:
            oslogin_enabled = True
        else:
            oslogin_enabled = False

        print(f"OS Login is enabled: {oslogin_enabled}")

# OSLogon with 2FA Check
@registry.register_check("gce")
def gce_instance_oslogon_2fa_access_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.GCE.11] Google Compute Engine VM instances configured to be accessed using OS Logon should enable 2FA
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    compute = googleapiclient.discovery.build('compute', 'v1')

    for gce in get_compute_engine_instances(cache, gcpProjectId):
        id = gce["id"]
        name = gce["name"]
        description = gce["description"]
        zone = gce["zone"].split('/')[-1]
        machineType = gce["machineType"].split('/')[-1]
        createdAt = gce["creationTimestamp"]
        lastStartedAt = gce["lastStartTimestamp"]
        status = gce["status"]
        # Check for Serial Port Access
        response = compute.instances().getSerialPortOutput(project=gcpProjectId, zone=zone, instance=id).execute()

        if "enable-oslogin" in response["metadata"]["items"]:
            oslogin_enabled = True
        else:
            oslogin_enabled = False

        if "enable-oslogin-2fa" in response["metadata"]["items"]:
            if response["metadata"]["items"]["enable-oslogin-2fa"] == "TRUE":
                oslogin_2fa_enabled = True
            else:
                oslogin_2fa_enabled = False
        else:
            oslogin_2fa_enabled = False

        print(f"OS Login is enabled: {oslogin_enabled}")
        print(f"OS Login with 2FA/MFA is enabled: {oslogin_2fa_enabled}")

# Public IP Check