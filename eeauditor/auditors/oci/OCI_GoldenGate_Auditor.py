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
                        "Text": "For more information autoscaling for your deployment refer to the Create a deployment section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
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
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 SA-13",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
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
                        "Text": "For more information autoscaling for your deployment refer to the Create a deployment section of the Oracle Cloud Infrastructure Documentation for Oracle GoldenGate.",
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
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 SA-13",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

# [OCI.GoldenGate.2] Oracle GoldenGate deployments should be reporting as healthy
# if deployment["is_healthy"] is False:
# https://docs.oracle.com/en-us/iaas/goldengate/doc/monitor-performance.html

# [OCI.GoldenGate.3] Oracle GoldenGate deployments should not be internet-facing
# if deployment["is_public"] is True:
# https://docs.oracle.com/en-us/iaas/goldengate/doc/securing-oci-goldengate.html

# [OCI.GoldenGate.4] Oracle GoldenGate deployments should be upgraded to the latest version if possible
# if deployment["is_latest_version"] is False:
# https://docs.oracle.com/pls/topic/lookup?ctx=en/cloud/paas/goldengate-service/ggscl&id=STZEE-GUID-7250B8AE-6CC1-43E4-94F9-E96E871E4A25

# [OCI.GoldenGate.5] Oracle GoldenGate deployments should have at least one Network Security Group (NSG) assigned
# if not deployment["nsg_ids"]:
# https://docs.oracle.com/en/cloud/paas/goldengate-service/scfws/#SCFWS-GUID-6C4B6D9B-E15B-44BB-BB98-08943BD3769A

# [OCI.GoldenGate.6] Oracle GoldenGate connections utilize private endpoints for network connectivity
# if not connection["ingress_ips"]:
# https://docs.oracle.com/en-us/iaas/goldengate/doc/create-connection-goldengate.html

# [OCI.GoldenGate.7] Oracle GoldenGate connections should be encrypted with a Customer-managed Master Encryption Key (MEK)
# if connection["key_id"] is None:
# https://docs.oracle.com/en-us/iaas/goldengate/doc/securing-oci-goldengate.html

# [OCI.GoldenGate.8] Oracle GoldenGate connections should have at least one Network Security Group (NSG) assigned
# if connection["nsg_ids"] is None:
# https://docs.oracle.com/en/cloud/paas/goldengate-service/scfws/#SCFWS-GUID-6C4B6D9B-E15B-44BB-BB98-08943BD3769A

# [OCI.GoldenGate.9] Oracle GoldenGate connections should protect incoming connections with TLS or Mutual TLS (mTLS)
# if connection["security_protocol"] == "PLAIN":
# https://docs.oracle.com/en-us/iaas/goldengate/doc/securing-oci-goldengate.html

## END ??