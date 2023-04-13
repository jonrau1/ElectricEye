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
    response = cache.get("get_cloudsql_dbs")
    if response:
        return response

    #  CloudSQL requires SQL Admin API - also doesnt need an aggregatedList
    service = googleapiclient.discovery.build('sqladmin', 'v1beta4')
    instances = service.instances().list(project=gcpProjectId).execute()
    
    cache["get_cloudsql_dbs"] = instances["items"]

    return cache["get_cloudsql_dbs"]

@registry.register_check("gce")
def cloudsql_instance_public_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.CloudSQL.1] CloudSQL Instances should not be publicly reachable
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        name = csql["name"]
        zone = csql["gceZone"]
        databaseInstalledVersion = csql["databaseInstalledVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # If this value is True, it means a Public IP is assigned
        if csql["ipConfiguration"]["ipv4Enabled"] == True:
            print(f"{name} in {zone} is public")
        else:
            print(f"{name} in {zone} is private ip")

# Backup Check backupConfiguration.enabled

# PITR MySQL Check backupConfiguration.binaryLogEnabled 

# PITR Postgresql Check backupConfiguration.pointInTimeRecoveryEnabled 

# Private Path Access ipConfiguration.enablePrivatePathForGoogleCloudServices

# Password Policy Enabled passwordValidationPolicy.enablePasswordPolicy

# Password Policy min length CIS (14) passwordValidationPolicy.minLength

# Password Policy Reuse CIS .reuseInterval

# Password Policy disallow username in PW .disallowUsernameSubstring

# Password Policy change interval .passwordChangeInterval

# Storage Autoresize storageAutoResize

# Deletion Protection deletionProtectionEnabled

# Enable Insights Config ... "insightsConfig": {},

# For Insights Config, Log Client IP insightsConfig.recordClientAddress

# Enforce SSL Connections ipConfiguration.requireSsl - can be missing 

# To be continued...?