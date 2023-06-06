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

def get_oci_load_balancers(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_oci_load_balancers")
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

    lbClient = oci.load_balancer.LoadBalancerClient(config)

    lbList = []

    for compartment in ociCompartments:
        listLbs = lbClient.list_load_balancers(compartment_id=compartment)
        for lb in listLbs.data:
            processedInstance = process_response(lb)
            lbList.append(processedInstance)

    cache["get_oci_load_balancers"] = lbList
    return cache["get_oci_load_balancers"]

def get_load_balancer_health(ociTenancyId, ociUserId, ociRegionName, ociUserApiKeyFingerprint, loadBalancerId):
    """
    This function retrieves the health status of a particular Load Balancer
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

    lbClient = oci.load_balancer.LoadBalancerClient(config)

    # Process & return the health status of a load balancer
    health = process_response(
        lbClient.get_load_balancer_health(
            load_balancer_id=loadBalancerId
        ).data
    )

    return health

@registry.register_check("oci.loadbalancer")
def oci_load_balancer_nsg_assigned_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.LoadBalancer.1] Load Balancers should have Network Security Groups (NSGs) assigned
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for loadbalancer in get_oci_load_balancers(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(loadbalancer,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = loadbalancer["compartment_id"]
        loadBalancerId = loadbalancer["id"]
        loadBalancerName = loadbalancer["display_name"]
        lbLifecycleState = loadbalancer["lifecycle_state"]
        createdAt = str(loadbalancer["time_created"])
        if not loadbalancer["network_security_group_ids"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-nsg-assigned-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-nsg-assigned-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.LoadBalancer.1] Load Balancers should have Network Security Groups (NSGs) assigned",
                "Description": f"Oracle Load Balancer {loadBalancerName} in Compartment {compartmentId} in {ociRegionName} does not have a Network Security Group (NSG) assigned. NSGs act as a virtual firewall for your compute instances and other kinds of resources. An NSG consists of a set of ingress and egress security rules that apply only to a set of VNICs of your choice in a single VCN (for example: all the compute instances that act as web servers in the web tier of a multi-tier application in your VCN). NSG security rules function the same as security list rules. However, for an NSG security rule's source (for ingress rules) or destination (for egress rules), you can specify an NSG instead of a CIDR. This means you can easily write security rules to control traffic between two NSGs in the same VCN, or traffic within a single NSG. See Parts of a Security Rule. Unlike with security lists, the VCN does not have a default NSG. Also, each NSG you create is initially empty. It has no default security rules. A network security group (NSG) provides a virtual firewall for a set of cloud resources that all have the same security posture. For example: a group of compute instances that all perform the same tasks and thus all need to use the same set of ports. If you have resources with different security postures in the same VCN, you can write NSG security rules to control traffic between the resources with one posture versus another. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Load Balancer should have a NSG assigned refer to the Network Security Groups section of the Oracle Cloud Infrastructure Documentation for Networks.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/networksecuritygroups.htm#support"
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
                    "AssetService": "Oracle Cloud Load Balancer",
                    "AssetComponent": "Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "OciCloudLoadBalancerLoadBalancer",
                        "Id": loadBalancerId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": loadBalancerName,
                                "Id": loadBalancerId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-nsg-assigned-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-nsg-assigned-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.LoadBalancer.1] Load Balancers should have Network Security Groups (NSGs) assigned",
                "Description": f"Oracle Load Balancer {loadBalancerName} in Compartment {compartmentId} in {ociRegionName} has a Network Security Group (NSG) assigned.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Load Balancer should have a NSG assigned refer to the Network Security Groups section of the Oracle Cloud Infrastructure Documentation for Networks.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/networksecuritygroups.htm#support",
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
                    "AssetService": "Oracle Cloud Load Balancer",
                    "AssetComponent": "Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "OciCloudLoadBalancerLoadBalancer",
                        "Id": loadBalancerId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": loadBalancerName,
                                "Id": loadBalancerId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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

@registry.register_check("oci.loadbalancer")
def oci_load_balancer_tls_listeners_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.LoadBalancer.2] Load Balancer listeners should be configured to use HTTPS/TLS
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for loadbalancer in get_oci_load_balancers(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(loadbalancer,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = loadbalancer["compartment_id"]
        loadBalancerId = loadbalancer["id"]
        loadBalancerName = loadbalancer["display_name"]
        lbLifecycleState = loadbalancer["lifecycle_state"]
        createdAt = str(loadbalancer["time_created"])
        # Use a list comprehension to set a "True" if a "ssl_configuration" is not empty (None), then override the variable based if any listener doesn't have TLS
        # while this shouldn't happen (multiple listeners with only one not being SSL) it's still possible
        listenerSsl = [True if loadbalancer["listeners"][listener]["ssl_configuration"] is not None else False for listener in loadbalancer["listeners"]]
        if False in listenerSsl:
            listenerSsl = False
        else:
            listenerSsl = True

        if listenerSsl is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-tls-listeners-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-tls-listeners-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.LoadBalancer.2] Load Balancer listeners should be configured to use HTTPS/TLS",
                "Description": f"Oracle Load Balancer {loadBalancerName} in Compartment {compartmentId} in {ociRegionName} has a Listener that is not configured to use HTTPS/TLS. To use standard SSL with a load balancer and its resources, you must supply a certificate. Oracle Cloud Infrastructure Certificates provides organizations with certificate issuance, storage, and management capabilities, including revocation and automatic renewal. If you have a third-party certificate authority (CA) that you already use, you can import certificates issued by that CA for use in an Oracle Cloud Infrastructure tenancy. Integration with Oracle Cloud Infrastructure Load Balancer lets you seamlessly associate a TLS certificate issued or managed by Certificates with resources that need certificates. The Load Balancer service does not generate SSL certificates. It can only import an existing certificate that you already own. The certificate can be one issued by a vendor, such as Verisign or GoDaddy. You can also use a self-signed certificate that you generate with an open source tool, such as OpenSSL or Let's Encrypt. Refer to the corresponding tool's documentation for instructions on how to generate a self-signed certificate. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Load Balancer should use TLS/HTTPS refer to the Configuring SSL Handling section of the Oracle Cloud Infrastructure Documentation for Load Balancers.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingcertificates.htm",
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
                    "AssetService": "Oracle Cloud Load Balancer",
                    "AssetComponent": "Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "OciCloudLoadBalancerLoadBalancer",
                        "Id": loadBalancerId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": loadBalancerName,
                                "Id": loadBalancerId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-tls-listeners-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-tls-listeners-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.LoadBalancer.2] Load Balancer listeners should be configured to use HTTPS/TLS",
                "Description": f"Oracle Load Balancer {loadBalancerName} in Compartment {compartmentId} in {ociRegionName} has all Listeners configured to use HTTPS/TLS.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Load Balancer should use TLS/HTTPS refer to the Configuring SSL Handling section of the Oracle Cloud Infrastructure Documentation for Load Balancers.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingcertificates.htm",
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
                    "AssetService": "Oracle Cloud Load Balancer",
                    "AssetComponent": "Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "OciCloudLoadBalancerLoadBalancer",
                        "Id": loadBalancerId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": loadBalancerName,
                                "Id": loadBalancerId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.loadbalancer")
def oci_load_balancer_tls_backend_set_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.LoadBalancer.3] Load Balancer backend sets should be configured to use HTTPS/TLS
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for loadbalancer in get_oci_load_balancers(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(loadbalancer,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = loadbalancer["compartment_id"]
        loadBalancerId = loadbalancer["id"]
        loadBalancerName = loadbalancer["display_name"]
        lbLifecycleState = loadbalancer["lifecycle_state"]
        createdAt = str(loadbalancer["time_created"])
        # Use a list comprehension to set a "True" if a "ssl_configuration" is not empty (None), then override the variable based if any backend sets doesn't have TLS
        backendSetSsl = [True if loadbalancer["backend_sets"][backendset]["ssl_configuration"] is not None else False for backendset in loadbalancer["backend_sets"]]
        if False in backendSetSsl:
            backendSetSsl = False
        else:
            backendSetSsl = True

        if backendSetSsl is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-tls-backend-set-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-tls-backend-set-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.LoadBalancer.3] Load Balancer backend sets should be configured to use HTTPS/TLS",
                "Description": f"Oracle Load Balancer {loadBalancerName} in Compartment {compartmentId} in {ociRegionName} has a Backend Set that is not configured to use HTTPS/TLS. To use standard SSL with a load balancer and its resources, you must supply a certificate. Oracle Cloud Infrastructure Certificates provides organizations with certificate issuance, storage, and management capabilities, including revocation and automatic renewal. If you have a third-party certificate authority (CA) that you already use, you can import certificates issued by that CA for use in an Oracle Cloud Infrastructure tenancy. Integration with Oracle Cloud Infrastructure Load Balancer lets you seamlessly associate a TLS certificate issued or managed by Certificates with resources that need certificates. The Load Balancer service does not generate SSL certificates. It can only import an existing certificate that you already own. The certificate can be one issued by a vendor, such as Verisign or GoDaddy. You can also use a self-signed certificate that you generate with an open source tool, such as OpenSSL or Let's Encrypt. Refer to the corresponding tool's documentation for instructions on how to generate a self-signed certificate. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Load Balancer should use TLS/HTTPS refer to the Configuring SSL Handling section of the Oracle Cloud Infrastructure Documentation for Load Balancers.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingcertificates.htm",
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
                    "AssetService": "Oracle Cloud Load Balancer",
                    "AssetComponent": "Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "OciCloudLoadBalancerLoadBalancer",
                        "Id": loadBalancerId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": loadBalancerName,
                                "Id": loadBalancerId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-tls-backend-set-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-tls-backend-set-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.LoadBalancer.3] Load Balancer backend sets should be configured to use HTTPS/TLS",
                "Description": f"Oracle Load Balancer {loadBalancerName} in Compartment {compartmentId} in {ociRegionName} has all Backend Sets configured to use HTTPS/TLS.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Load Balancer should use TLS/HTTPS refer to the Configuring SSL Handling section of the Oracle Cloud Infrastructure Documentation for Load Balancers.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingcertificates.htm",
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
                    "AssetService": "Oracle Cloud Load Balancer",
                    "AssetComponent": "Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "OciCloudLoadBalancerLoadBalancer",
                        "Id": loadBalancerId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": loadBalancerName,
                                "Id": loadBalancerId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.loadbalancer")
def oci_load_balancer_unhealthy_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.LoadBalancer.4] Load Balancers with health checks reporting Critical or Warning should be investigated
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for loadbalancer in get_oci_load_balancers(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(loadbalancer,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = loadbalancer["compartment_id"]
        loadBalancerId = loadbalancer["id"]
        loadBalancerName = loadbalancer["display_name"]
        lbLifecycleState = loadbalancer["lifecycle_state"]
        createdAt = str(loadbalancer["time_created"])
        # Get health status
        health = get_load_balancer_health(ociTenancyId, ociUserId, ociRegionName, ociUserApiKeyFingerprint, loadBalancerId)
        if health["status"] == "CRITICAL":
            status = "critical"
            unhealthyStatus = True
            auditorSeverity = "HIGH"
        elif health["status"] == "WARNING":
            status = "warning"
            unhealthyStatus = True
            auditorSeverity = "MEDIUM"
        else:
            status = "healthy"
            unhealthyStatus = False
            auditorSeverity = "INFORMATIONAL"

        if unhealthyStatus is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-unhealthy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-unhealthy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": auditorSeverity},
                "Confidence": 99,
                "Title": "[OCI.LoadBalancer.4] Load Balancers with health checks reporting Critical or Warning should be investigated",
                "Description": f"Oracle Load Balancer {loadBalancerName} in Compartment {compartmentId} in {ociRegionName} is reporting as {status} and should be investigated. At the highest level, load balancer health reflects the health of its components. The health status indicators provide information you might need to drill down and investigate an existing issue. Some common issues that the health status indicators can help you detect and correct include: misconfigured health checks, listeners, security rules and/or unhealthy backend servers. Health status is updated every three minutes. No finer granularity is available. Other cases in which health status might prove helpful include: NSGs or Security Lists block traffic or Cloud Compute instances have misconfigured route tables. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the potential underlying issues contributing to your load balancer health refer to the Understanding Load Balancer Health Issues section of the Oracle Cloud Infrastructure Documentation for Load Balancers.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/understanding_health_issues.htm#UnderstandingHealthStatus",
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
                    "AssetService": "Oracle Cloud Load Balancer",
                    "AssetComponent": "Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "OciCloudLoadBalancerLoadBalancer",
                        "Id": loadBalancerId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": loadBalancerName,
                                "Id": loadBalancerId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-unhealthy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{loadBalancerId}/oci-load-balancer-unhealthy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": auditorSeverity},
                "Confidence": 99,
                "Title": "[OCI.LoadBalancer.4] Load Balancers with health checks reporting Critical or Warning should be investigated",
                "Description": f"Oracle Load Balancer {loadBalancerName} in Compartment {compartmentId} in {ociRegionName} is reporting as {status}.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the potential underlying issues contributing to your load balancer health refer to the Understanding Load Balancer Health Issues section of the Oracle Cloud Infrastructure Documentation for Load Balancers.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/understanding_health_issues.htm#UnderstandingHealthStatus",
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
                    "AssetService": "Oracle Cloud Load Balancer",
                    "AssetComponent": "Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "OciCloudLoadBalancerLoadBalancer",
                        "Id": loadBalancerId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": loadBalancerName,
                                "Id": loadBalancerId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??