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

from azure.mgmt.network import NetworkManagementClient, models
from os import path
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

# Filename of the SG Auditor config JSON file
dirPath = path.dirname(path.realpath(__file__))
try:
    configFile = f"{dirPath}/electriceye_nsg_auditor_config.json"
except Exception as e:
    raise e

def get_all_azure_nsgs(cache: dict, azureCredential, azSubId: str) -> list[models._models.NetworkSecurityGroup]:
    """
    Returns a list of all NSGs in a Subscription
    """
    azNetworkClient = NetworkManagementClient(azureCredential,azSubId)

    response = cache.get("get_all_azure_nsgs")
    if response:
        return response
    
    nsgList = [nsg for nsg in azNetworkClient.network_security_groups.list_all()]
    if not nsgList or nsgList is None:
        nsgList = []

    cache["get_all_azure_nsgs"] = nsgList
    return cache["get_all_azure_nsgs"]

@registry.register_check("azure.networ_security_groups")
def azure_network_security_group_all_open_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """[Azure.NetworkSecurityGroup.1] Azure network security groups should not allow unrestricted access to all ports and protocols"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for secgroup in get_all_azure_nsgs(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(secgroup.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        nsgName = secgroup.name
        nsgId = str(secgroup.id)
        azRegion = secgroup.location
        rgName = nsgId.split("/")[4]
        allowAll = False
        for rule in secgroup.security_rules:
            if (
                rule.destination_port_range == "*" 
                and rule.source_port_range == "*" 
                and rule.protocol == "*" 
                and rule.destination_address_prefix == "*"
                and not rule.destination_address_prefixes
            ):
                allowAll = True
                break

        # this is a failing check
        if allowAll is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{nsgId}/azure-network-security-group-all-open-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{nsgId}/azure-network-security-group-all-open-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[Azure.NetworkSecurityGroup.1] Azure network security groups should not allow unrestricted access to all ports and protocols",
                "Description": f"Azure Database for PostgreSQL Server {nsgName} in Subscription {azSubId} in {azRegion} contains a rule that allows unrestricted access to all ports and protocols. Network Security Groups are often the first line of defense for network boundaries in Azure, allowing unfettered access removes an important part of a cloud security defense-in-depth and makes it easier for adversaries to perform recon on your assets and potentially gain unauthorized access where no other network-based controls exist. Your network security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements. Additionally, ensure that Azure WAF, Azure Front Door, or some other self-managed host- or network-based appliance exists to interdict and prevent adversarial network traffic from reaching your hosts.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Network Security Groups refer to the How network security groups filter network traffic section of the Azure Virtual Network documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Azure Network Security Group",
                    "AssetComponent": "Network Security Group"
                },
                "Resources": [
                    {
                        "Type": "AzureNetworkSecurityGroup",
                        "Id": nsgId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": nsgName,
                                "Id": nsgId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.2",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.4",
                        "MITRE ATT&CK T1021.001",
                        "MITRE ATT&CK T1021.004",
                        "MITRE ATT&CK T1095",
                        "MITRE ATT&CK T1190",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{nsgId}/azure-network-security-group-all-open-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{nsgId}/azure-network-security-group-all-open-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.NetworkSecurityGroup.1] Azure network security groups should not allow unrestricted access to all ports and protocols",
                "Description": f"Azure Database for PostgreSQL Server {nsgName} in Subscription {azSubId} in {azRegion} contains a rule that allows unrestricted access to all ports and protocols. Network Security Groups are often the first line of defense for network boundaries in Azure, allowing unfettered access removes an important part of a cloud security defense-in-depth and makes it easier for adversaries to perform recon on your assets and potentially gain unauthorized access where no other network-based controls exist. Your network security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements. Additionally, ensure that Azure WAF, Azure Front Door, or some other self-managed host- or network-based appliance exists to interdict and prevent adversarial network traffic from reaching your hosts.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Network Security Groups refer to the How network security groups filter network traffic section of the Azure Virtual Network documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Azure Network Security Group",
                    "AssetComponent": "Network Security Group"
                },
                "Resources": [
                    {
                        "Type": "AzureNetworkSecurityGroup",
                        "Id": nsgId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": nsgName,
                                "Id": nsgId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.2",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.4",
                        "MITRE ATT&CK T1021.001",
                        "MITRE ATT&CK T1021.004",
                        "MITRE ATT&CK T1095",
                        "MITRE ATT&CK T1190",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.networ_security_groups")
def azure_network_security_group_master_auditor_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """[Azure.NetworkSecurityGroup.{checkIdNumber}] Azure network security groups should not allow unrestricted {protocol} access"""
    # compliance requirements mappings - depending on the protocol some additional controls will be appended
    complianceReqs = [
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
        "ISO 27001:2013 A.13.2.1"
    ]
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Open the Configuration file and parse the information within the dynamically populate this auditor
    with open(configFile, "r") as jsonfile:
        for x in json.load(jsonfile):
            destinationPortRange = str(x["ToPort"])
            if destinationPortRange == "3389":
                complianceReqs = complianceReqs + ["CIS Microsoft Azure Foundations Benchmark V2.0.0 6.1","MITRE ATT&CK T1021.001"]
            if destinationPortRange == "22":
                complianceReqs = complianceReqs + ["CIS Microsoft Azure Foundations Benchmark V2.0.0 6.2","MITRE ATT&CK T1021.004"]
            if destinationPortRange == "443":
                complianceReqs = complianceReqs + ["CIS Microsoft Azure Foundations Benchmark V2.0.0 6.4","MITRE ATT&CK T1190"]        
            targetProtocol = x["Protocol"]
            checkTitle = x["CheckTitle"]
            checkId = x["CheckId"]
            checkDescription = x["CheckDescriptor"]
            for secgroup in get_all_azure_nsgs(cache, azureCredential, azSubId):
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(secgroup.as_dict(),default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                nsgName = secgroup.name
                nsgId = str(secgroup.id)
                azRegion = secgroup.location
                rgName = nsgId.split("/")[4]
                for rule in secgroup.security_rules:
                    # this is a failing check
                    if (
                        destinationPortRange in str(rule.destination_port_range)
                        and rule.source_port_range == "*" 
                        and str(rule.protocol).lower() == targetProtocol 
                        and rule.destination_address_prefix == "*"
                        and not rule.destination_address_prefixes
                    ):
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{azRegion}/{nsgId}/{targetProtocol}/{checkId}",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": f"{azRegion}/{nsgId}/{checkId}",
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                                "Effects/Data Exposure",
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": checkTitle,
                            "Description": f"Azure Database for PostgreSQL Server {nsgName} in Subscription {azSubId} in {azRegion} contains a rule that allows unrestricted {checkDescription} access. Network Security Groups are often the first line of defense for network boundaries in Azure, allowing unfettered access removes an important part of a cloud security defense-in-depth and makes it easier for adversaries to perform recon on your assets and potentially gain unauthorized access where no other network-based controls exist. Your network security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements. Additionally, ensure that Azure WAF, Azure Front Door, or some other self-managed host- or network-based appliance exists to interdict and prevent adversarial network traffic from reaching your hosts.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on Network Security Groups refer to the How network security groups filter network traffic section of the Azure Virtual Network documentation.",
                                    "Url": "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "Azure",
                                "ProviderType": "CSP",
                                "ProviderAccountId": azSubId,
                                "AssetRegion": azRegion,
                                "AssetDetails": assetB64,
                                "AssetClass": "Networking",
                                "AssetService": "Azure Network Security Group",
                                "AssetComponent": "Network Security Group"
                            },
                            "Resources": [
                                {
                                    "Type": "AzureNetworkSecurityGroup",
                                    "Id": nsgId,
                                    "Partition": awsPartition,
                                    "Region": azRegion,
                                    "Details": {
                                        "Other": {
                                            "SubscriptionId": azSubId,
                                            "ResourceGroupName": rgName,
                                            "Region": azRegion,
                                            "Name": nsgName,
                                            "Id": nsgId
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": complianceReqs
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{azRegion}/{nsgId}/{targetProtocol}/{checkId}",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": f"{azRegion}/{nsgId}/{checkId}",
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                                "Effects/Data Exposure",
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": checkTitle,
                            "Description": f"Azure Database for PostgreSQL Server {nsgName} in Subscription {azSubId} in {azRegion} does not contain a rule that allows unrestricted {checkDescription} access.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on Network Security Groups refer to the How network security groups filter network traffic section of the Azure Virtual Network documentation.",
                                    "Url": "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "Azure",
                                "ProviderType": "CSP",
                                "ProviderAccountId": azSubId,
                                "AssetRegion": azRegion,
                                "AssetDetails": assetB64,
                                "AssetClass": "Networking",
                                "AssetService": "Azure Network Security Group",
                                "AssetComponent": "Network Security Group"
                            },
                            "Resources": [
                                {
                                    "Type": "AzureNetworkSecurityGroup",
                                    "Id": nsgId,
                                    "Partition": awsPartition,
                                    "Region": azRegion,
                                    "Details": {
                                        "Other": {
                                            "SubscriptionId": azSubId,
                                            "ResourceGroupName": rgName,
                                            "Region": azRegion,
                                            "Name": nsgName,
                                            "Id": nsgId
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": complianceReqs
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding

## END ??