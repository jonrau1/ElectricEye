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

def get_cloudsql_dbs(cache: dict, gcpProjectId: str):
    '''
    AggregatedList result provides Zone information as well as every single Instance in a Project
    '''
    if cache:
        return cache
    
    results = []

    cloudsql = googleapiclient.discovery.build('sqladmin', 'v1beta4')

    aggResult = cloudsql.instances().aggregatedList(project=gcpProjectId).execute()

    import json

    with open('./agg_csql.json', 'w') as jsonfile:
        json.dump(aggResult, jsonfile, indent=2)

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
def cloudsql_instance_public_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.CloudSQL.1] CloudSQL Instances should not be publicly reachable
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    get_cloudsql_dbs(cache, gcpProjectId)


    """for gce in get_cloudsql_dbs(cache, gcpProjectId):
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
            yield finding"""

# To be continued...?