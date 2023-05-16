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

def get_instance_configurations(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_instance_configurations")
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

    computeMgmtClient = oci.core.ComputeManagementClient(config)

    aSlightlyConfigurableListOfInstanceConfigurations = []

    for compartment in ociCompartments:
        for template in process_response(computeMgmtClient.list_instance_configurations(compartment_id=compartment).data):
            aSlightlyConfigurableListOfInstanceConfigurations.append(
                process_response(
                    computeMgmtClient.get_instance_configuration(instance_configuration_id=template["id"]).data
                )
            )

    cache["get_instance_configurations"] = aSlightlyConfigurableListOfInstanceConfigurations
    return cache["get_instance_configurations"]


# [OCI.InstanceConfiguration.1] Oracle Cloud Compute Instance Configurations should define that the Vulnerability Scanning agent is enabled on instances
# List comprehension on config["instance_details"]["launch_details"]["agent_config"]["plugins_config"] for plugin["name"] == "Vulnerability Scanning" if plugin["desired_state"] == "ENABLED"

# [OCI.InstanceConfiguration.2] Oracle Cloud Compute Instance Configurations should define that the OS Management Service Agent agent is enabled on instances
# List comprehension on config["instance_details"]["launch_details"]["agent_config"]["plugins_config"] for plugin["name"] == "OS Management Service Agent" if plugin["desired_state"] == "ENABLED"

# [OCI.InstanceConfiguration.3] Oracle Cloud Compute Instance Configurations should define that the Management Agent agent is enabled on instances
# List comprehension on config["instance_details"]["launch_details"]["agent_config"]["plugins_config"] for plugin["name"] == "Management Agent" if plugin["desired_state"] == "ENABLED"

# [OCI.InstanceConfiguration.4] Oracle Cloud Compute Instance Configurations should define that the Compute Instance Run Command agent is enabled on instances
# List comprehension on config["instance_details"]["launch_details"]["agent_config"]["plugins_config"] for plugin["name"] == "Compute Instance Run Command" if plugin["desired_state"] == "ENABLED"

# [OCI.InstanceConfiguration.5] Oracle Cloud Compute Instance Configurations should define that public IP addresses are not assigned to instances unless absolutely required
# if config["instance_details"]["launch_details"]["create_vnic_details"]["assign_public_ip"] is True:

# [OCI.InstanceConfiguration.6] Oracle Cloud Compute Instance Configurations should define that instances are protected with Network Security Groups (NSGs)
# if config["instance_details"]["launch_details"]["create_vnic_details"]["nsg_ids"] is None:

# [OCI.InstanceConfiguration.7] Oracle Cloud Compute Instance Configurations should define that instances do not enable Instance Metadata Service version 1 (IMDSv1)
# if config["instance_details"]["launch_details"]["instance_options"]["are_legacy_imds_endpoints_disabled"] is False:

# [OCI.InstanceConfiguration.8] Oracle Cloud Compute Instance Configurations should define that instances enable paravirutalized volume in-transit encryption
# if config["instance_details"]["launch_details"]["is_pv_encryption_in_transit_enabled"] is False:

# [OCI.InstanceConfiguration.9] Oracle Cloud Compute Instance Configurations should define that instances enable Secure Boot
# if config["instance_details"]["launch_details"]["platform_config"]["is_secure_boot_enabled"] is False:

# [OCI.InstanceConfiguration.10] Oracle Cloud Compute Instance Configurations should define that instances enable Measured Boot
# if config["instance_details"]["launch_details"]["platform_config"]["is_measured_boot_enabled"] is False:

# [OCI.InstanceConfiguration.11] Oracle Cloud Compute Instance Configurations should define that instances enable the Trusted Platform Module (TPM)
# if config["instance_details"]["launch_details"]["platform_config"]["is_trusted_platform_module_enabled"] is False:

# [OCI.InstanceConfiguration.12] Oracle Cloud Compute Instance Configurations should define that instances are encrypted with a Customer-managed Master Encryption Key (MEK)
# if config["instance_details"]["launch_details"]["source_details"]["kms_key_id"] is None: