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
import base64
import json

registry = CheckRegister()

def get_service_network_with_metadata(cache, session):
    response = cache.get("get_service_network_with_metadata")
    
    if response:
        return response
        
    vpclattice = session.client("vpc-lattice")
    
    serviceNetworksWithMetadata = []
    
    # Get the Service Networks, we will need to retrieve Authentication Policies & Logging Configuration and add them as needed
    for snetwork in vpclattice.list_service_networks()["items"]:
        serviceNetworkPayload = vpclattice.get_service_network(serviceNetworkIdentifier=snetwork["id"])
        # Remove the metadata on response, we need to use the Get API to get the "authType"
        del serviceNetworkPayload["ResponseMetadata"]
        # Check if we need to get the auth policy first
        if serviceNetworkPayload["authType"] == "NONE":
            serviceNetworkPayload["authPolicy"] = None
        else:
            authPolicy = vpclattice.get_auth_policy(
                resourceIdentifier=snetwork["id"]
            )
            if "policy" not in authPolicy:
                serviceNetworkPayload["authPolicy"] = None
            else:
                serviceNetworkPayload["authPolicy"] = json.loads(authPolicy["policy"])
            del authPolicy
        # Get the access log subscriptions
        serviceNetworkPayload["accessLogSubscriptions"] = vpclattice.list_access_log_subscriptions(resourceIdentifier=snetwork["id"])["items"]
        
        serviceNetworksWithMetadata.append(serviceNetworkPayload)
        
    cache["get_service_network_with_metadata"] = serviceNetworksWithMetadata
    return cache["get_service_network_with_metadata"]

def get_services_with_metadata(cache, session):
    response = cache.get("get_services_with_metadata")
    
    if response:
        return response
        
    vpclattice = session.client("vpc-lattice")
    
    servicesWithMetadata = []

    for service in vpclattice.list_services()["items"]:
        servicePayload = vpclattice.get_service(serviceIdentifier=service["id"])
        # Remove the metadata on response, we need to use the Get API to get the "authType"
        del servicePayload["ResponseMetadata"]
        # Check if we need to get the auth policy first
        if servicePayload["authType"] == "NONE":
            servicePayload["authPolicy"] = None
        else:
            authPolicy = vpclattice.get_auth_policy(
                resourceIdentifier=service["id"]
            )
            if "policy" not in authPolicy:
                servicePayload["authPolicy"] = None
            else:
                servicePayload["authPolicy"] = json.loads(authPolicy["policy"])
            del authPolicy
        # Get the access log subscriptions
        servicePayload["accessLogSubscriptions"] = vpclattice.list_access_log_subscriptions(resourceIdentifier=service["id"])["items"]
        
        servicesWithMetadata.append(servicePayload)

    cache["get_services_with_metadata"] = servicesWithMetadata
    return cache["get_services_with_metadata"]

def get_target_groups_with_metadata(cache, session):
    response = cache.get("get_target_groups_with_metadata")
    
    if response:
        return response
        
    vpclattice = session.client("vpc-lattice")
    
    targetGroupsWithMetadata = []

    for tgroup in vpclattice.list_target_groups()["items"]:
        targetGroupPayload = vpclattice.get_target_group(targetGroupIdentifier=tgroup["id"])
        del targetGroupPayload["ResponseMetadata"]
        targetGroupsWithMetadata.append(targetGroupPayload)

    cache["get_services_with_metadata"] = targetGroupsWithMetadata
    return cache["get_services_with_metadata"]

def get_listeners_with_metadata(cache, session):
    response = cache.get("get_listeners_with_metadata")
    
    if response:
        return response
        
    vpclattice = session.client("vpc-lattice")

    listenersWithMetadata = []

    for service in vpclattice.list_services()["items"]:
        serviceId = service["id"]
        listeners = vpclattice.list_listeners(serviceIdentifier=serviceId)["items"]
        if listeners:
            for listener in listeners:
                listenerPayload = vpclattice.get_listener(
                    listenerIdentifier=listener["id"],
                    serviceIdentifier=serviceId
                )
                del listenerPayload["ResponseMetadata"]
                listenersWithMetadata.append(listenerPayload)
    
    cache["get_listeners_with_metadata"] = listenersWithMetadata
    return cache["get_listeners_with_metadata"]

@registry.register_check("vpc-lattice")
def aws_vpc_lattice_service_network_vpc_association_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC-Lattice.1] VPC Lattice service networks should be associated with at least one Amazon Virtual Private Cloud (VPC)"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for servicenetwork in get_service_network_with_metadata(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(servicenetwork,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        serviceNetworkArn = servicenetwork["arn"]
        serviceNetworkId = servicenetwork["id"]
        # this is a failing check
        if servicenetwork["numberOfAssociatedVPCs"] == 0:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-vpc-association-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-vpc-association-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[VPC-Lattice.1] VPC Lattice service networks should be associated with at least one Amazon Virtual Private Cloud (VPC)",
                "Description": f"AWS VPC Lattice service network {serviceNetworkId} is not associated with at least one Amazon Virtual Private Cloud (VPC). When you associate a service with the service network, it enables clients (resources in a VPC associated with the service network), to make requests to the service. When you associate a VPC with the service network, it enables all the targets within that VPC to be clients and communicate with other services in the service network. Clients can send requests to services associated with the service network only if they are in VPCs associated with the service network. Client traffic that traverses a VPC peering connection or a transit gateway is denied. Service networks not associated with VPCs are essentially defunct and in best cases only consume billing & quotas, and at worse, can be maliciously modified to allow access to adversary-controlled networks. If this configuration is not intended refer to the remediation instructions.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on managing associations (VPC and Service) for your VPC Lattice Service Networks refer to the Manage the associations for a service network section of the AWS VPC Lattice User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc-lattice/latest/ug/service-network-associations.html"
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
                    "AssetService": "AWS VPC Lattice",
                    "AssetComponent": "Service Network"
                },
                "Resources": [
                    {
                        "Type": "AwsVpcLatticeServiceNetwork",
                        "Id": serviceNetworkArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": serviceNetworkId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-vpc-association-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-vpc-association-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC-Lattice.1] VPC Lattice service networks should be associated with at least one Amazon Virtual Private Cloud (VPC)",
                "Description": f"AWS VPC Lattice service network {serviceNetworkId} is associated with at least one Amazon Virtual Private Cloud (VPC).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on managing associations (VPC and Service) for your VPC Lattice Service Networks refer to the Manage the associations for a service network section of the AWS VPC Lattice User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc-lattice/latest/ug/service-network-associations.html"
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
                    "AssetService": "AWS VPC Lattice",
                    "AssetComponent": "Service Network"
                },
                "Resources": [
                    {
                        "Type": "AwsVpcLatticeServiceNetwork",
                        "Id": serviceNetworkArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": serviceNetworkId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("vpc-lattice")
def aws_vpc_lattice_service_network_service_association_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC-Lattice.2] VPC Lattice service networks should be associated with at least one VPC Lattice Service"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for servicenetwork in get_service_network_with_metadata(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(servicenetwork,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        serviceNetworkArn = servicenetwork["arn"]
        serviceNetworkId = servicenetwork["id"]
        # this is a failing check
        if servicenetwork["numberOfAssociatedServices"] == 0:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-service-association-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-service-association-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[VPC-Lattice.2] VPC Lattice service networks should be associated with at least one VPC Lattice Service",
                "Description": f"AWS VPC Lattice service network {serviceNetworkId} is not associated with at least one VPC Lattice Service. When you associate a service with the service network, it enables clients (resources in a VPC associated with the service network), to make requests to the service. When you associate a VPC with the service network, it enables all the targets within that VPC to be clients and communicate with other services in the service network. You can associate services that reside in your account or services that are shared with you from different accounts. This is an optional step while creating a service network. However, a service network is not fully functional until you associate a service. Service networks not associated with services are essentially defunct and in best cases only consume billing & quotas, and at worse, can be maliciously modified to allow access to adversary-controlled networks. If this configuration is not intended refer to the remediation instructions.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on managing associations (VPC and Service) for your VPC Lattice Service Networks refer to the Manage the associations for a service network section of the AWS VPC Lattice User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc-lattice/latest/ug/service-network-associations.html"
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
                    "AssetService": "AWS VPC Lattice",
                    "AssetComponent": "Service Network"
                },
                "Resources": [
                    {
                        "Type": "AwsVpcLatticeServiceNetwork",
                        "Id": serviceNetworkArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": serviceNetworkId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-service-association-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-service-association-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC-Lattice.2] VPC Lattice service networks should be associated with at least one VPC Lattice Service",
                "Description": f"AWS VPC Lattice service network {serviceNetworkId} is associated with at least one VPC Lattice Service.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on managing associations (VPC and Service) for your VPC Lattice Service Networks refer to the Manage the associations for a service network section of the AWS VPC Lattice User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc-lattice/latest/ug/service-network-associations.html"
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
                    "AssetService": "AWS VPC Lattice",
                    "AssetComponent": "Service Network"
                },
                "Resources": [
                    {
                        "Type": "AwsVpcLatticeServiceNetwork",
                        "Id": serviceNetworkArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": serviceNetworkId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("vpc-lattice")
def aws_vpc_lattice_service_network_iam_auth_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC-Lattice.3] VPC Lattice service networks should enable AWS IAM authentication to apply coarse-grained access restrictions"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for servicenetwork in get_service_network_with_metadata(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(servicenetwork,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        serviceNetworkArn = servicenetwork["arn"]
        serviceNetworkId = servicenetwork["id"]
        # this is a failing check
        if servicenetwork["authType"] != "AWS_IAM":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-aws-iam-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-aws-iam-auth-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC-Lattice.3] VPC Lattice service networks should enable AWS IAM authentication to apply coarse-grained access restrictions",
                "Description": f"AWS VPC Lattice service network {serviceNetworkId} does not enable AWS IAM authentication to apply coarse-grained access restrictions. Access settings enable you to configure and manage client access to a service network. Access settings include auth type and auth policies. Auth policies help you authenticate and authorize traffic flowing to services within VPC Lattice. You can apply auth policies at the service network level, the service level, or both. Typically, auth policies are applied by the network owners or cloud administrators. They can implement course-grained authorization, for example, allowing authenticated calls from within the organization, or allowing anonymous GET requests that match a certain condition, to apply a resource policy to the service network, choose AWS IAM for Auth type. If this configuration is not intended refer to the remediation instructions.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting auth type and auth policies for your VPC Lattice Service Networks refer to the Edit access settings for a service network section of the AWS VPC Lattice User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc-lattice/latest/ug/service-network-access.html"
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
                    "AssetService": "AWS VPC Lattice",
                    "AssetComponent": "Service Network"
                },
                "Resources": [
                    {
                        "Type": "AwsVpcLatticeServiceNetwork",
                        "Id": serviceNetworkArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": serviceNetworkId
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
                "Id": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-aws-iam-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-aws-iam-auth-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC-Lattice.3] VPC Lattice service networks should enable AWS IAM authentication to apply coarse-grained access restrictions",
                "Description": f"AWS VPC Lattice service network {serviceNetworkId} does enable AWS IAM authentication to apply coarse-grained access restrictions.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting auth type and auth policies for your VPC Lattice Service Networks refer to the Edit access settings for a service network section of the AWS VPC Lattice User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc-lattice/latest/ug/service-network-access.html"
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
                    "AssetService": "AWS VPC Lattice",
                    "AssetComponent": "Service Network"
                },
                "Resources": [
                    {
                        "Type": "AwsVpcLatticeServiceNetwork",
                        "Id": serviceNetworkArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": serviceNetworkId
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

@registry.register_check("vpc-lattice")
def aws_vpc_lattice_service_network_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC-Lattice.4] VPC Lattice service networks should enable a form of logging"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for servicenetwork in get_service_network_with_metadata(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(servicenetwork,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        serviceNetworkArn = servicenetwork["arn"]
        serviceNetworkId = servicenetwork["id"]
        # this is a failing check
        if not servicenetwork["accessLogSubscriptions"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC-Lattice.4] VPC Lattice service networks should enable a form of logging",
                "Description": f"AWS VPC Lattice service network {serviceNetworkId} does not enable a form of logging. Access logs capture detailed information about your VPC Lattice services. You can use these access logs to analyze traffic patterns and audit all of the services in the network. Access logs are optional and are disabled by default. After you enable access logs, you can disable them at any time. You can send access logs to the following destinations: Amazon CloudWatch Logs, Amazon S3, or Amazon Kinesis Data Firehose. You can enable access logs for a service network or for a service during creation. You can also enable access logs after you create a service network or service. If this configuration is not intended refer to the remediation instructions.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring different types of logging for your VPC Lattice Service Networks refer to the Access logs for VPC Lattice section of the AWS VPC Lattice User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc-lattice/latest/ug/monitoring-access-logs.html"
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
                    "AssetService": "AWS VPC Lattice",
                    "AssetComponent": "Service Network"
                },
                "Resources": [
                    {
                        "Type": "AwsVpcLatticeServiceNetwork",
                        "Id": serviceNetworkArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": serviceNetworkId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC-Lattice.4] VPC Lattice service networks should enable a form of logging",
                "Description": f"AWS VPC Lattice service network {serviceNetworkId} does enable a form of logging.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring different types of logging for your VPC Lattice Service Networks refer to the Access logs for VPC Lattice section of the AWS VPC Lattice User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc-lattice/latest/ug/monitoring-access-logs.html"
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
                    "AssetService": "AWS VPC Lattice",
                    "AssetComponent": "Service Network"
                },
                "Resources": [
                    {
                        "Type": "AwsVpcLatticeServiceNetwork",
                        "Id": serviceNetworkArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": serviceNetworkId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("vpc-lattice")
def aws_vpc_lattice_service_network_minimal_auth_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC-Lattice.5] VPC Lattice service networks should define an auth policy with minimized access using conditions"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for servicenetwork in get_service_network_with_metadata(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(servicenetwork,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        serviceNetworkArn = servicenetwork["arn"]
        serviceNetworkId = servicenetwork["id"]
        # Evaluate if IAM Auth is used at all (by the presence of a Auth Policy) and then simply check if there is a condition
        # at the bare minimum, a condition trumps even unfettered Resource and Principal Access
        if servicenetwork["authPolicy"] is None:
            conditionInPolicy = False
        else:
            for statement in servicenetwork["authPolicy"]["Statement"]:
                if "Condition" not in statement:
                    conditionInPolicy = False
                    break
                else:
                    conditionInPolicy = True
        # this is a failing check
        if conditionInPolicy is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-minimal-auth-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-minimal-auth-policy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC-Lattice.5] VPC Lattice service networks should define an auth policy with minimized access using conditions",
                "Description": f"AWS VPC Lattice service network {serviceNetworkId} does not define an auth policy with minimized access using conditions. VPC Lattice auth policies are IAM policy documents that you attach to service networks or services to control whether a specified principal has access to a group of services or specific service. You can attach one auth policy to each service network or service that you want to control access to. VPC Lattice auth policies are specified using the same syntax as IAM policies. Access can be further controlled by condition keys in the Condition element of auth policies. These condition keys are present for evaluation depending on the protocol and whether the request is signed with Signature Version 4 (SigV4) or anonymous, additionally, you can conditionalize access based on headers, paths, ports, request methods, query strings, source VPCs, and more. If this configuration is not intended refer to the remediation instructions.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring coarse-grained access policies with conditional statements for your VPC Lattice Service Networks refer to the Control access to services using auth policies section of the AWS VPC Lattice User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc-lattice/latest/ug/auth-policies.html#auth-policies-condition-keys"
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
                    "AssetService": "AWS VPC Lattice",
                    "AssetComponent": "Service Network"
                },
                "Resources": [
                    {
                        "Type": "AwsVpcLatticeServiceNetwork",
                        "Id": serviceNetworkArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": serviceNetworkId
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
                "Id": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-minimal-auth-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{serviceNetworkArn}/aws-vpc-lattice-service-network-minimal-auth-policy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC-Lattice.5] VPC Lattice service networks should define an auth policy with minimized access using conditions",
                "Description": f"AWS VPC Lattice service network {serviceNetworkId} does define an auth policy with minimized access using conditions.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring coarse-grained access policies with conditional statements for your VPC Lattice Service Networks refer to the Control access to services using auth policies section of the AWS VPC Lattice User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc-lattice/latest/ug/auth-policies.html#auth-policies-condition-keys"
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
                    "AssetService": "AWS VPC Lattice",
                    "AssetComponent": "Service Network"
                },
                "Resources": [
                    {
                        "Type": "AwsVpcLatticeServiceNetwork",
                        "Id": serviceNetworkArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": serviceNetworkId
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

## EOF?