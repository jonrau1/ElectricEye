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
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

# Filename of the SL Auditor config JSON file
dirPath = os.path.dirname(os.path.realpath(__file__))
configFile = f"{dirPath}/electriceye_oci_vcn_seclist_auditor_config.json"

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

def get_oci_security_lists(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_oci_security_lists")
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

    vcnClient = oci.core.VirtualNetworkClient(config)

    anActualListOfSecurityLists = []

    for compartment in ociCompartments:
        for sl in vcnClient.list_security_lists(compartment_id=compartment).data:
            anActualListOfSecurityLists.append(
                process_response(
                    sl
                )
            )

    cache["get_oci_security_lists"] = anActualListOfSecurityLists
    return cache["get_oci_security_lists"]

@registry.register_check("oci.vcn.securitylist")
def oci_vcn_security_list_all_open_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """"[OCI.SecurityList.1] Virtual Cloud Network Security Lists should not allow unrestricted access to all ports and protocols"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for seclist in get_oci_security_lists(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(seclist, default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = seclist["compartment_id"]
        seclistName = seclist["display_name"]
        seclistId = seclist["id"]
        vcnId = seclist["vcn_id"]
        lifecycleState = seclist["lifecycle_state"]
        createdAt = seclist["time_created"]
        # Create a list comprehension to scope down the amount of rules that need to be looked at
        allowAllCheck = [rule for rule in seclist["ingress_security_rules"] if rule.get("protocol") == "all" and rule.get("source") == "0.0.0.0/0"]
        # If the list has an entry that means there is at least one rule that allows all ports & protocols
        if allowAllCheck:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{seclistId}/oci-load-balancer-nsg-assigned-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{seclistId}/oci-load-balancer-nsg-assigned-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[OCI.SecurityList.1] Virtual Cloud Network Security Lists should not allow unrestricted access to all ports and protocols",
                "Description": f"Virtual Cloud Network Security Lists {seclistName} for VCN {vcnId} in Compartment {compartmentId} in {ociRegionName} contains a rule that allows unrestricted access to all ports and protocols. An Oracle Cloud Security List is a virtual firewall that acts as the first line of defense for networks in OCI. It is used to define network access rules that control inbound and outbound traffic to and from subnets, instances, and other resources in a virtual cloud network (VCN). Allowing unfettered access removes an important part of a cloud security defense-in-depth and makes it easier for adversaries to perform recon on your assets and potentially gain unauthorized access where no other network-based controls exist. Your security list should still be audited to ensure any other rules are compliant with organizational or regulatory requirements. Additionally, audit that other network security controls such as Network Security Groups, Web Application Firewalls, Network Firewalls, and other host- and network-based appliances and services are configured to mitigate the risk posed by this Security List. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on building and modifying Security Rules (for NSGs and SLs) refer to the Security Rules section of the Oracle Cloud Infrastructure Documentation for Networks.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm#sec_rules_parts",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Oracle Cloud Virtual Cloud Network",
                    "AssetComponent": "Security List"
                },
                "Resources": [
                    {
                        "Type": "OciVcnSecurityList",
                        "Id": seclistId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": seclistName,
                                "Id": seclistId,
                                "VirtualCloudNetworkId": vcnId,
                                "CreatedAt": createdAt,
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{seclistId}/oci-load-balancer-nsg-assigned-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{seclistId}/oci-load-balancer-nsg-assigned-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.SecurityList.1] Virtual Cloud Network Security Lists should not allow unrestricted access to all ports and protocols",
                "Description": f"Virtual Cloud Network Security Lists {seclistName} for VCN {vcnId} in Compartment {compartmentId} in {ociRegionName} does not contain a rule that allows unrestricted access to all ports and protocols.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on building and modifying Security Rules (for NSGs and SLs) refer to the Security Rules section of the Oracle Cloud Infrastructure Documentation for Networks.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm#sec_rules_parts",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Oracle Cloud Virtual Cloud Network",
                    "AssetComponent": "Security List"
                },
                "Resources": [
                    {
                        "Type": "OciVcnSecurityList",
                        "Id": seclistId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": seclistName,
                                "Id": seclistId,
                                "VirtualCloudNetworkId": vcnId,
                                "CreatedAt": createdAt,
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.vcn.securitylist")
def oci_vcn_security_list_all_open_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """"[OCI.SecurityList.{checkIdNumber}] Virtual Cloud Network Security Lists should not allow unrestricted {protocol} access"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Open the Configuration file and parse the information within the dynamically populate this auditor
    with open(configFile, 'r') as jsonfile:
        auditRules = json.load(jsonfile)
    # Grab Sec Lists from Cache
    for seclist in get_oci_security_lists(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(seclist, default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = seclist["compartment_id"]
        seclistName = seclist["display_name"]
        seclistId = seclist["id"]
        vcnId = seclist["vcn_id"]
        lifecycleState = seclist["lifecycle_state"]
        createdAt = seclist["time_created"]
        for x in json.load(auditRules):
            toPortTarget = x["ToPort"]
            fromPortTarget = x["FromPort"]
            targetProtocol = x["Protocol"]
            checkTitle = x["CheckTitle"]
            checkId = x["CheckId"]
            checkDescription = x["CheckDescriptor"]
            if targetProtocol == "17":
                portFilterDict = "udp_options"
            elif targetProtocol == "6":
                portFilterDict = "tcp_options"
            else:
                continue

            print(f"Auditing all OCI VCN Security List {seclistName} for unrestricted {checkDescription} access")
            # Create a list comprehension to scope down the amount of rules that need to be looked at
            filteredRules = [
                rule for rule in seclist["ingress_security_rules"] 
                if rule.get("protocol") == targetProtocol 
                and rule.get("source") == "0.0.0.0/0"
                and rule[portFilterDict]["source_port_range"].get("max") == toPortTarget
                and rule[portFilterDict]["source_port_range"].get("min") == fromPortTarget
            ]


            print(f"{checkId} {str(filteredRules)}")


            """allowAllCheck = [rule for rule in seclist["ingress_security_rules"] if rule.get("protocol") == "all" and rule.get("source") == "0.0.0.0/0"]
            # If the list has an entry that means there is at least one rule that allows all ports & protocols
            if allowAllCheck:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{seclistId}/oci-load-balancer-nsg-assigned-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{seclistId}/oci-load-balancer-nsg-assigned-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "CRITICAL"},
                    "Confidence": 99,
                    "Title": "[OCI.SecurityList.1] Virtual Cloud Network Security Lists should not allow unrestricted access to all ports and protocols",
                    "Description": f"Virtual Cloud Network Security Lists {seclistName} for VCN {vcnId} in Compartment {compartmentId} in {ociRegionName} contains a rule that allows unrestricted access to all ports and protocols. An Oracle Cloud Security List is a virtual firewall that acts as the first line of defense for networks in OCI. It is used to define network access rules that control inbound and outbound traffic to and from subnets, instances, and other resources in a virtual cloud network (VCN). Allowing unfettered access removes an important part of a cloud security defense-in-depth and makes it easier for adversaries to perform recon on your assets and potentially gain unauthorized access where no other network-based controls exist. Your security list should still be audited to ensure any other rules are compliant with organizational or regulatory requirements. Additionally, audit that other network security controls such as Network Security Groups, Web Application Firewalls, Network Firewalls, and other host- and network-based appliances and services are configured to mitigate the risk posed by this Security List. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on building and modifying Security Rules (for NSGs and SLs) refer to the Security Rules section of the Oracle Cloud Infrastructure Documentation for Networks.",
                            "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm#sec_rules_parts",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "OCI",
                        "ProviderType": "CSP",
                        "ProviderAccountId": ociTenancyId,
                        "AssetRegion": ociRegionName,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Oracle Cloud Virtual Cloud Network",
                        "AssetComponent": "Security List"
                    },
                    "Resources": [
                        {
                            "Type": "OciVcnSecurityList",
                            "Id": seclistId,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "TenancyId": ociTenancyId,
                                    "CompartmentId": compartmentId,
                                    "Region": ociRegionName,
                                    "Name": seclistName,
                                    "Id": seclistId,
                                    "VirtualCloudNetworkId": vcnId,
                                    "CreatedAt": createdAt,
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
                    "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{seclistId}/oci-load-balancer-nsg-assigned-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{seclistId}/oci-load-balancer-nsg-assigned-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[OCI.SecurityList.1] Virtual Cloud Network Security Lists should not allow unrestricted access to all ports and protocols",
                    "Description": f"Virtual Cloud Network Security Lists {seclistName} for VCN {vcnId} in Compartment {compartmentId} in {ociRegionName} does not contain a rule that allows unrestricted access to all ports and protocols.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on building and modifying Security Rules (for NSGs and SLs) refer to the Security Rules section of the Oracle Cloud Infrastructure Documentation for Networks.",
                            "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm#sec_rules_parts",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "OCI",
                        "ProviderType": "CSP",
                        "ProviderAccountId": ociTenancyId,
                        "AssetRegion": ociRegionName,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Oracle Cloud Virtual Cloud Network",
                        "AssetComponent": "Security List"
                    },
                    "Resources": [
                        {
                            "Type": "OciVcnSecurityList",
                            "Id": seclistId,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "TenancyId": ociTenancyId,
                                    "CompartmentId": compartmentId,
                                    "Region": ociRegionName,
                                    "Name": seclistName,
                                    "Id": seclistId,
                                    "VirtualCloudNetworkId": vcnId,
                                    "CreatedAt": createdAt,
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
                            "ISO 27001:2013 A.13.2.1"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding"""