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

def get_block_storage_volumes(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_block_storage_volumes")
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

    blockStorageClient = oci.core.BlockstorageClient(config)

    aBigBlockyListOfBlockyBois = []

    for compartment in ociCompartments:
        for blockyboi in process_response(blockStorageClient.list_volumes(compartment_id=compartment).data):
            # Get
            blockyBoiBackupPolicyAssignment = process_response(blockStorageClient.get_volume_backup_policy_asset_assignment(asset_id=blockyboi["id"]).data)
            blockyboi["backup_policy"] = blockyBoiBackupPolicyAssignment
            aBigBlockyListOfBlockyBois.append(blockyboi)

    cache["get_block_storage_volumes"] = aBigBlockyListOfBlockyBois
    return cache["get_block_storage_volumes"]

# [OCI.BlockStorage.1] Oracle Cloud Block Storage volumes with high availability and enhanced resilience requirements should use replication
# if volume["block_volume_replicas"] is None:


# [OCI.BlockStorage.2] Oracle Cloud Block Storage volumes should use an auto-tune policy
# if volume["is_auto_tune_enabled"] is False:


# [OCI.BlockStorage.3] Oracle Cloud Block Storage volumes should be encrypted with a Customer-managed Master Encryption Key (MEK)
# if volume["kms_key_id"] is None:


# [OCI.BlockStorage.4] Oracle Cloud Block Storage volumes should be a member of a Block Volume Group
# if volume["volume_group_id"] is None:


# [OCI.BlockStorage.5] Oracle Cloud Block Storage volumes be configured to take automated backups
# if not volume["backup_policy"]:


## END ??