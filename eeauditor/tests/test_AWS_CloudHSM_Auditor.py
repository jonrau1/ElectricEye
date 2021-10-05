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
import json
import os
import pytest

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.AWS_CloudHSM_Auditor import (
    cloudhsm_cluster_degradation_check,
    cloudhsm_hsm_degradation_check,
    cloudhsm_cluster_backup_check,
    cloudhsm
)

describe_clusters_degraded = {
    'Clusters': [
        {
            'ClusterId': 'string',
            'CreateTimestamp': datetime.datetime(2015, 1, 1),
            'Hsms': [
                {
                    'AvailabilityZone': 'string',
                    'ClusterId': 'cluster12345',
                    'SubnetId': 'string',
                    'EniId': 'string',
                    'EniIp': 'string',
                    'HsmId': 'string',
                    'State': 'DEGRADED',
                    'StateMessage': 'string'
                },
            ],
            'State': 'DEGRADED',
        }
    ]
}

describe_clusters_not_degraded = {
    'Clusters': [
        {
            'ClusterId': 'string',
            'CreateTimestamp': datetime.datetime(2015, 1, 1),
            'Hsms': [
                {
                    'AvailabilityZone': 'string',
                    'ClusterId': 'cluster12345',
                    'SubnetId': 'string',
                    'EniId': 'string',
                    'EniIp': 'string',
                    'HsmId': 'string',
                    'State': 'ACTIVE',
                    'StateMessage': 'string'
                },
            ],
            'State': 'ACTIVE',
        }
    ]
}

describe_backups_active = {
    'Backups': [
        {
            'BackupId': 'backup1234',
            'BackupState': 'READY',
            'ClusterId': 'cluster12345',
        },
    ],
}

describe_backups_blank = {
    'Backups': [],
}


describe_backups_multiple_deleted = {
    'Backups': [
        {
            'BackupId': 'backup1234',
            'BackupState': 'DELETED',
            'ClusterId': 'cluster12345',
        },
        {
            'BackupId': 'backup345',
            'BackupState': 'PENDING_DELETION',
            'ClusterId': 'cluster12345',
        },
        {
            'BackupId': 'backup678',
            'BackupState': 'CREATE_IN_PROGRESS',
            'ClusterId': 'cluster12345',
        },
    ],
}

@pytest.fixture(scope="function")
def cloudhsm_stubber():
    cloudhsm_stubber = Stubber(cloudhsm)
    cloudhsm_stubber.activate()
    yield cloudhsm_stubber
    cloudhsm_stubber.deactivate()


def test_cloudhsm_cluster_degradation_degraded_check(cloudhsm_stubber):
    cloudhsm_stubber.add_response("describe_clusters", describe_clusters_degraded)
    results = cloudhsm_cluster_degradation_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudhsm_stubber.assert_no_pending_responses()


def test_cloudhsm_cluster_degradation_not_degraded_check(cloudhsm_stubber):
    cloudhsm_stubber.add_response("describe_clusters", describe_clusters_not_degraded)
    results = cloudhsm_cluster_degradation_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudhsm_stubber.assert_no_pending_responses()


def test_cloudhsm_hsm_degradation_degraded_check(cloudhsm_stubber):
    cloudhsm_stubber.add_response("describe_clusters", describe_clusters_degraded)
    results = cloudhsm_hsm_degradation_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudhsm_stubber.assert_no_pending_responses()


def test_cloudhsm_hsm_degradation_not_degraded_check(cloudhsm_stubber):
    cloudhsm_stubber.add_response("describe_clusters", describe_clusters_not_degraded)
    results = cloudhsm_hsm_degradation_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudhsm_stubber.assert_no_pending_responses()


def test_cloudhsm_cluster_ready_backup_check(cloudhsm_stubber):
    cloudhsm_stubber.add_response("describe_clusters", describe_clusters_degraded)
    cloudhsm_stubber.add_response("describe_backups", describe_backups_active)
    results = cloudhsm_cluster_backup_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    cloudhsm_stubber.assert_no_pending_responses()


def test_cloudhsm_cluster_blank_backup_check(cloudhsm_stubber):
    cloudhsm_stubber.add_response("describe_clusters", describe_clusters_degraded)
    cloudhsm_stubber.add_response("describe_backups", describe_backups_blank)
    results = cloudhsm_cluster_backup_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudhsm_stubber.assert_no_pending_responses()


def test_cloudhsm_cluster_multiple_deleted_backup_check(cloudhsm_stubber):
    cloudhsm_stubber.add_response("describe_clusters", describe_clusters_degraded)
    cloudhsm_stubber.add_response("describe_backups", describe_backups_multiple_deleted)
    results = cloudhsm_cluster_backup_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    cloudhsm_stubber.assert_no_pending_responses()