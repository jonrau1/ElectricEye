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

def get_golden_gate_deployments(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_golden_gate_deployments")
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

    ggClient = oci.golden_gate.GoldenGateClient(config)

    aBigListOfGoldenBois = []

    for compartment in ociCompartments:
        for deployment in process_response(ggClient.list_deployments(compartment_id=compartment).data)["items"]:
            aBigListOfGoldenBois.append(
                process_response(
                    ggClient.get_deployment(deployment_id=deployment["id"]).data
                )
            )

    cache["get_golden_gate_deployments"] = aBigListOfGoldenBois
    return cache["get_golden_gate_deployments"]

def get_golden_gate_connections(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_golden_gate_connections")
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

    ggClient = oci.golden_gate.GoldenGateClient(config)

    aConnectedListOfConnections = []

    for compartment in ociCompartments:
        for connection in process_response(ggClient.list_connections(compartment_id=compartment).data)["items"]:
            aConnectedListOfConnections.append(
                process_response(
                    ggClient.get_connection(connection_id=connection["id"]).data
                )
            )

    cache["get_golden_gate_connections"] = aConnectedListOfConnections
    return cache["get_golden_gate_connections"]

@registry.register_check("oci.goldengate")
def oci_goldengate_deployment_autoscaling_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.GoldenGate.1] Oracle GoldenGate deployments should be configured for Oracle CPU (OCPU) autoscaling
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for deployment in get_golden_gate_deployments(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(deployment,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = deployment["compartment_id"]
        deploymentId = deployment["id"]
        deploymentName = deployment["display_name"]
        lifecycleState = deployment["lifecycle_state"]
        createdAt = str(deployment["time_created"])

        if deployment["is_auto_scaling_enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-autoscaling-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-autoscaling-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.1] Oracle GoldenGate deployments should be configured for Oracle CPU (OCPU) autoscaling",
                "Description": f"Oracle GoldenGate deployment {deploymentName} in Compartment {compartmentId} in {ociRegionName} is not configured for Oracle CPU (OCPU) autoscaling. Auto scaling enables OCI GoldenGate to scale up to three times the number of OCPUs you specify for OCPU Count, up to 24 OCPUs. For example, if you specify your OCPU Count as 2 and enable Auto Scaling, then your deployment can scale up to 6 OCPUs. If you specify your OCPU Count as 20 and enable Auto Scaling, OCI GoldenGate can only scale up to 24 OCPUs. One OCPU is equivalent to 16gb of memory, allowing scaling to be handled automatically can help ensure against outages due to demands outstripping forecast and can further aid in an overall business continuity or disaster recovery strategy that utilizes Oracle GoldenGate. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about auto-scaling for your deployment refer to the Create a deployment section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en-us/iaas/goldengate/doc/create-deployment.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Deployment"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateDeployment",
                        "Id": deploymentId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": deploymentName,
                                "Id": deploymentId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-autoscaling-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-autoscaling-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.1] Oracle GoldenGate deployments should be configured for Oracle CPU (OCPU) autoscaling",
                "Description": f"Oracle GoldenGate deployment {deploymentName} in Compartment {compartmentId} in {ociRegionName} is configured for Oracle CPU (OCPU) autoscaling.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about auto-scaling for your deployment refer to the Create a deployment section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en-us/iaas/goldengate/doc/create-deployment.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Migration & Transfer",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Deployment"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateDeployment",
                        "Id": deploymentId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": deploymentName,
                                "Id": deploymentId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.goldengate")
def oci_goldengate_deployment_healthy_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.GoldenGate.2] Oracle GoldenGate deployments should be reporting as healthy
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for deployment in get_golden_gate_deployments(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(deployment,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = deployment["compartment_id"]
        deploymentId = deployment["id"]
        deploymentName = deployment["display_name"]
        lifecycleState = deployment["lifecycle_state"]
        createdAt = str(deployment["time_created"])

        if deployment["is_healthy"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-healthy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-healthy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.2] Oracle GoldenGate deployments should be reporting as healthy",
                "Description": f"Oracle GoldenGate deployment {deploymentName} in Compartment {compartmentId} in {ociRegionName} is not reporting as healthy. Observe and maintain the health of your OCI GoldenGate resources by regularly monitoring metrics, creating alarms, and subscribing to events to keep informed of any abnormal activity among your resources. Ensure that you upgrade your deployment to the latest version to leverage all available metrics. The Deployment Overall Health metric is the health score of the deployment, which is the aggregate health of the deployment's processes (Administration, Distribution, Receiver, and Performance Metric Services). If a Deployment is reporting unhealthy it means that multiple metrics across compute, memory, storage, and/or connectivity have critical failures and should be investigated. If you are utilizing GoldenGate as part of your overall business continuity or disaster recovery strategy for databases ensuring Deployments stay healthy or can recover quickly is even more paramount for effective BC/DR and change management processes. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about metrics and reporting health for your deployment refer to the Monitor performance in the Oracle Cloud console section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en-us/iaas/goldengate/doc/monitor-performance.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Deployment"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateDeployment",
                        "Id": deploymentId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": deploymentName,
                                "Id": deploymentId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-healthy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-healthy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.2] Oracle GoldenGate deployments should be reporting as healthy",
                "Description": f"Oracle GoldenGate deployment {deploymentName} in Compartment {compartmentId} in {ociRegionName} is reporting as healthy.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about metrics and reporting health for your deployment refer to the Monitor performance in the Oracle Cloud console section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en-us/iaas/goldengate/doc/monitor-performance.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Deployment"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateDeployment",
                        "Id": deploymentId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": deploymentName,
                                "Id": deploymentId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

@registry.register_check("oci.goldengate")
def oci_goldengate_deployment_public_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.GoldenGate.3] Oracle GoldenGate deployments should not be internet-facing
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for deployment in get_golden_gate_deployments(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(deployment,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = deployment["compartment_id"]
        deploymentId = deployment["id"]
        deploymentName = deployment["display_name"]
        lifecycleState = deployment["lifecycle_state"]
        createdAt = str(deployment["time_created"])

        if deployment["is_public"] is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-public-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-public-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.3] Oracle GoldenGate deployments should not be internet-facing",
                "Description": f"Oracle GoldenGate deployment {deploymentName} in Compartment {compartmentId} in {ociRegionName} is internet-facing. Oracle Cloud Infrastructure GoldenGate provides a secure and easy to use data replication solution in accordance with industry-leading security best practices. Encrypted access to the OCI GoldenGate deployment console is enabled over SSL on port 443 only. By default, only access to the OCI GoldenGate deployment console is only available from an OCI private endpoint from the customer's private network. Public endpoints can be configured allowing encrypted public access to the GoldenGate Deployment Console over SSL on port 443. Limit privileges as much as possible, users should be given only the access necessary to perform their work and connectivity should be limited as much as possible. If a publicly-reachable GoldenGate deployment is required, consider place it behind an Oracle Load Balancer and utilizing extra network security measures such as Oracle WAF, Network Firewall, and/or NSGs to only permit small network segments or utilize a VPN and have a private deployment. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about overall security for your deployment refer to the Securing OCI GoldenGate section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en-us/iaas/goldengate/doc/securing-oci-goldengate.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Deployment"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateDeployment",
                        "Id": deploymentId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": deploymentName,
                                "Id": deploymentId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-public-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-public-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.3] Oracle GoldenGate deployments should not be internet-facing",
                "Description": f"Oracle GoldenGate deployment {deploymentName} in Compartment {compartmentId} in {ociRegionName} is not internet-facing.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about overall security for your deployment refer to the Securing OCI GoldenGate section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en-us/iaas/goldengate/doc/securing-oci-goldengate.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Deployment"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateDeployment",
                        "Id": deploymentId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": deploymentName,
                                "Id": deploymentId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

@registry.register_check("oci.goldengate")
def oci_goldengate_deployment_latest_version_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.GoldenGate.4] Oracle GoldenGate deployments should be upgraded to the latest version if possible
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for deployment in get_golden_gate_deployments(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(deployment,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = deployment["compartment_id"]
        deploymentId = deployment["id"]
        deploymentName = deployment["display_name"]
        lifecycleState = deployment["lifecycle_state"]
        createdAt = str(deployment["time_created"])

        if deployment["is_latest_version"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-latest-version-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-latest-version-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.4] Oracle GoldenGate deployments should be upgraded to the latest version if possible",
                "Description": f"Oracle GoldenGate deployment {deploymentName} in Compartment {compartmentId} in {ociRegionName} is not upgraded to the latest version. OCI GoldenGate supports multiple concurrent versions, for example, Oracle GoldenGate, Oracle GoldenGate for Big Data, and Oracle GoldenGate for MySQL, to name a few. Deployments must be upgraded when a newer version is available. Depending on the type of release and whether or not it includes a security fix, you have a specific amount of time to upgrade: 1 year for non-security related Major versions and 180 days for non-security related Bundle versions but for Security-related releases you must upgrade Bundle and Minor versions in 14 days. If you don't upgrade manually within the given timeframe, then your deployment automatically upgrades to the latest version at the end of this timeframe. The aforementioned upgrade timeframes are the same for version deprecation schedules. If your use case supports using the latest versions, ensure you upgrade as soon as possible through proper change management processes. Additionally, ensure you have a process to rapidly test new security-fix related versions to create development requirements to upgrade other dependent code. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about version upgrades and deprecation for your deployment refer to the Maintain your OCI GoldenGate deployments section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/pls/topic/lookup?ctx=en/cloud/paas/goldengate-service/ggscl&id=STZEE-GUID-7250B8AE-6CC1-43E4-94F9-E96E871E4A25"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Deployment"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateDeployment",
                        "Id": deploymentId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": deploymentName,
                                "Id": deploymentId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-latest-version-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-latest-version-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.4] Oracle GoldenGate deployments should be upgraded to the latest version if possible",
                "Description": f"Oracle GoldenGate deployment {deploymentName} in Compartment {compartmentId} in {ociRegionName} is using the latest version.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about version upgrades and deprecation for your deployment refer to the Maintain your OCI GoldenGate deployments section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/pls/topic/lookup?ctx=en/cloud/paas/goldengate-service/ggscl&id=STZEE-GUID-7250B8AE-6CC1-43E4-94F9-E96E871E4A25"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Deployment"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateDeployment",
                        "Id": deploymentId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": deploymentName,
                                "Id": deploymentId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
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

@registry.register_check("oci.goldengate")
def oci_goldengate_deployment_uses_nsgs_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.GoldenGate.5] Oracle GoldenGate deployments should have at least one Network Security Group (NSG) assigned
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for deployment in get_golden_gate_deployments(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(deployment,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = deployment["compartment_id"]
        deploymentId = deployment["id"]
        deploymentName = deployment["display_name"]
        lifecycleState = deployment["lifecycle_state"]
        createdAt = str(deployment["time_created"])

        if not deployment["nsg_ids"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-use-nsgs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-use-nsgs-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.5] Oracle GoldenGate deployments should have at least one Network Security Group (NSG) assigned",
                "Description": f"Oracle GoldenGate deployment {deploymentName} in Compartment {compartmentId} in {ociRegionName} does not have a Network Security Group (NSG) assigned. NSGs act as a virtual firewall for your compute instances and other kinds of resources. An NSG consists of a set of ingress and egress security rules that apply only to a set of VNICs of your choice in a single VCN (for example: all the compute instances that act as web servers in the web tier of a multi-tier application in your VCN). NSG security rules function the same as security list rules. When you create an OCI GoldenGate deployment, you can enable or disable the deployment's public endpoint. Because the OCI GoldenGate Public Endpoint is managed by the OCI GoldenGate service tenancy, it's not possible for you to create network security group (NSG) rules from your customer tenancy. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about configuring NSGs for your deployment refer to the Task 5: Create OCI Network Security Rules to allow/deny ingress section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en/cloud/paas/goldengate-service/scfws/#SCFWS-GUID-6C4B6D9B-E15B-44BB-BB98-08943BD3769A"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Deployment"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateDeployment",
                        "Id": deploymentId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": deploymentName,
                                "Id": deploymentId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-use-nsgs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{deploymentId}/oci-goldengate-deployment-use-nsgs-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.5] Oracle GoldenGate deployments should have at least one Network Security Group (NSG) assigned",
                "Description": f"Oracle GoldenGate deployment {deploymentName} in Compartment {compartmentId} in {ociRegionName} does have a Network Security Group (NSG) assigned.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about configuring NSGs for your deployment refer to the Task 5: Create OCI Network Security Rules to allow/deny ingress section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en/cloud/paas/goldengate-service/scfws/#SCFWS-GUID-6C4B6D9B-E15B-44BB-BB98-08943BD3769A"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Deployment"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateDeployment",
                        "Id": deploymentId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": deploymentName,
                                "Id": deploymentId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

@registry.register_check("oci.goldengate")
def oci_goldengate_connection_private_endpoints_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.GoldenGate.6] Oracle GoldenGate connections utilize private endpoints for network connectivity
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for connection in get_golden_gate_connections(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(connection,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = connection["compartment_id"]
        connectionId = connection["id"]
        connectionName = connection["display_name"]
        lifecycleState = connection["lifecycle_state"]
        createdAt = str(connection["time_created"])

        if not connection["ingress_ips"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-private-endpoints-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-private-endpoints-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.6] Oracle GoldenGate connections utilize private endpoints for network connectivity",
                "Description": f"Oracle GoldenGate connection {connectionName} in Compartment {compartmentId} in {ociRegionName} does not utilize private endpoints for network connectivity. The Oracle GoldenGate connection type lets you create connections to other Oracle GoldenGate deployments. For example, replicate data between a MySQL database and Kafka, you need a MySQL deployment type and a Big Data deployment type. The Oracle GoldenGate deployment lets you create a connection between the two deployment types. These two deployment types need not be in the same compartment or tenancy. Create the connection to the Oracle GoldenGate deployment that initiates the replication. Under Network connectivity, select Network connectivity via private endpoint if the GoldenGate deployment can only be accessed through a private IP. his creates a network route for the OCI GoldenGate deployment to connect to the database within your customer tenancy. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about configuring your connection refer to the Create a connection to Oracle GoldenGate deployments section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en-us/iaas/goldengate/doc/create-connection-goldengate.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Connection"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateConnection",
                        "Id": connectionId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": connectionName,
                                "Id": connectionId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-private-endpoints-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-private-endpoints-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.6] Oracle GoldenGate connections utilize private endpoints for network connectivity",
                "Description": f"Oracle GoldenGate connection {connectionName} in Compartment {compartmentId} in {ociRegionName} does utilize private endpoints for network connectivity.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about configuring your connection refer to the Create a connection to Oracle GoldenGate deployments section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en-us/iaas/goldengate/doc/create-connection-goldengate.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Connection"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateConnection",
                        "Id": connectionId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": connectionName,
                                "Id": connectionId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

@registry.register_check("oci.goldengate")
def oci_goldengate_connection_use_cmk_mek_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.GoldenGate.7] Oracle GoldenGate connections should be encrypted with a Customer-managed Master Encryption Key (MEK)
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for connection in get_golden_gate_connections(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(connection,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = connection["compartment_id"]
        connectionId = connection["id"]
        connectionName = connection["display_name"]
        lifecycleState = connection["lifecycle_state"]
        createdAt = str(connection["time_created"])

        if connection["key_id"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.7] Oracle GoldenGate connections should be encrypted with a Customer-managed Master Encryption Key (MEK)",
                "Description": f"Oracle GoldenGate connection {connectionName} in Compartment {compartmentId} in {ociRegionName} does not use a Customer-managed Master Encryption Key (MEK). Use master encryption keys to encrypt trail files distributed to other GoldenGate deployments. You can then import and export master encryption key wallets to use with other source and target OCI GoldenGate deployments. If a master key is created in Oracle GoldenGate, then each time GoldenGate creates a trail file, it automatically generates a new encryption key that encrypts the trail contents. The master key encrypts the encryption key. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about using Wallets and Vault MEKs for your connection refer to the Manage master encryption key wallets section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en-us/iaas/goldengate/doc/manage-master-encryption-key-wallets.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Connection"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateConnection",
                        "Id": connectionId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": connectionName,
                                "Id": connectionId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.7] Oracle GoldenGate connections should be encrypted with a Customer-managed Master Encryption Key (MEK)",
                "Description": f"Oracle GoldenGate connection {connectionName} in Compartment {compartmentId} in {ociRegionName} does use a Customer-managed Master Encryption Key (MEK).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about using Wallets and Vault MEKs for your connection refer to the Manage master encryption key wallets section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en-us/iaas/goldengate/doc/manage-master-encryption-key-wallets.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Connection"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateConnection",
                        "Id": connectionId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": connectionName,
                                "Id": connectionId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.goldengate")
def oci_goldengate_connection_use_nsg_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.GoldenGate.8] Oracle GoldenGate connections should have at least one Network Security Group (NSG) assigned
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for connection in get_golden_gate_connections(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(connection,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = connection["compartment_id"]
        connectionId = connection["id"]
        connectionName = connection["display_name"]
        lifecycleState = connection["lifecycle_state"]
        createdAt = str(connection["time_created"])

        if connection["nsg_ids"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-nsgs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-nsgs-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.8] Oracle GoldenGate connections should have at least one Network Security Group (NSG) assigned",
                "Description": f"Oracle GoldenGate connection {connectionName} in Compartment {compartmentId} in {ociRegionName} does not have a Network Security Group (NSG) assigned. NSGs act as a virtual firewall for your compute instances and other kinds of resources. An NSG consists of a set of ingress and egress security rules that apply only to a set of VNICs of your choice in a single VCN (for example: all the compute instances that act as web servers in the web tier of a multi-tier application in your VCN). NSG security rules function the same as security list rules. When you create an OCI GoldenGate deployment, you can enable or disable the deployment's public endpoint. Because the OCI GoldenGate Public Endpoint is managed by the OCI GoldenGate service tenancy, it's not possible for you to create network security group (NSG) rules from your customer tenancy. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about configuring NSGs for your deployment refer to the Task 5: Create OCI Network Security Rules to allow/deny ingress section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en/cloud/paas/goldengate-service/scfws/#SCFWS-GUID-6C4B6D9B-E15B-44BB-BB98-08943BD3769A"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Connection"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateConnection",
                        "Id": connectionId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": connectionName,
                                "Id": connectionId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-nsgs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-nsgs-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.8] Oracle GoldenGate connections should have at least one Network Security Group (NSG) assigned",
                "Description": f"Oracle GoldenGate connection {connectionName} in Compartment {compartmentId} in {ociRegionName} does have a Network Security Group (NSG) assigned.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about configuring NSGs for your deployment refer to the Task 5: Create OCI Network Security Rules to allow/deny ingress section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en/cloud/paas/goldengate-service/scfws/#SCFWS-GUID-6C4B6D9B-E15B-44BB-BB98-08943BD3769A"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Connection"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateConnection",
                        "Id": connectionId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": connectionName,
                                "Id": connectionId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

@registry.register_check("oci.goldengate")
def oci_goldengate_connection_use_tls_mtls_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.GoldenGate.9] Oracle GoldenGate connections should protect incoming connections with TLS or Mutual TLS (mTLS)
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for connection in get_golden_gate_connections(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(connection,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = connection["compartment_id"]
        connectionId = connection["id"]
        connectionName = connection["display_name"]
        lifecycleState = connection["lifecycle_state"]
        createdAt = str(connection["time_created"])

        if connection["security_protocol"] == "PLAIN":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-tls-mtls-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-tls-mtls-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.9] Oracle GoldenGate connections should protect incoming connections with TLS or Mutual TLS (mTLS)",
                "Description": f"Oracle GoldenGate connection {connectionName} in Compartment {compartmentId} in {ociRegionName} does not use TLS or Mutual TLS (mTLS). Communication security is the confidentiality and integrity of the information sent over communications channels, such as TCP/IP-based networks. Secure communication implies confidentiality and integrity of data sent over communications channels, such as TCP/IP-based networks. It uses cryptographic protocols to provide communication security over the network. The communication security accepts a valid certificate during the connection handshake process. The certificate must be signed by the server or for CA it must trusted by the server. However, you may need to filter and reject otherwise valid certificates based on internal policies. To support this additional validation, the MA extends the standard certificate validation by adding a post-verification certificate Access Control List (ACL) management. This certificate ACL follows the general model used for network ACLs where the ACL is a map with the key identifying the governed element and a value indicating whether the element is allowed or denied. The certACL entry has a scopespecification that allows the ACL entry to be applied to specific identification elements within a certificate. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about configuring TLS for your connections refer to the TLS and Secure Network Protocols section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en/middleware/goldengate/core/19.1/securing/communications-security.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Connection"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateConnection",
                        "Id": connectionId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": connectionName,
                                "Id": connectionId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-tls-mtls-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{connectionId}/oci-goldengate-connection-use-tls-mtls-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.GoldenGate.9] Oracle GoldenGate connections should protect incoming connections with TLS or Mutual TLS (mTLS)",
                "Description": f"Oracle GoldenGate connection {connectionName} in Compartment {compartmentId} in {ociRegionName} does use TLS or Mutual TLS (mTLS).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information about configuring TLS for your connections refer to the TLS and Secure Network Protocols section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
                        "Url": "https://docs.oracle.com/en/middleware/goldengate/core/19.1/securing/communications-security.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle GoldenGate",
                    "AssetComponent": "Connection"
                },
                "Resources": [
                    {
                        "Type": "OciGoldenGateConnection",
                        "Id": connectionId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": connectionName,
                                "Id": connectionId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

## END ??