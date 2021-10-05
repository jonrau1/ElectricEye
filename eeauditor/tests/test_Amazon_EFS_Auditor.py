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
import os
import pytest
import sys
import botocore

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.Amazon_EFS_Auditor import (
    efs_filesys_encryption_check,
    describe_file_systems,
    efs_filesys_policy_check,
    efs
)

describe_file_systems = {
    "FileSystems": [{
        "FileSystemId": "MyEFS",
        "OwnerId": "Owner12345",
        "CreationToken": 'egCreationToken',
        "CreationTime": '2015-01-01',
        "LifeCycleState": 'available',
        "NumberOfMountTargets": 1,
        "SizeInBytes": {'Value': 123,'Timestamp': '2015-01-01','ValueInIA': 123,'ValueInStandard': 123},
        "PerformanceMode": "generalPurpose",
        "Encrypted": True,
        "Tags": [{'Key': 'EgKey', 'Value': 'EgValue'}]
    }]
}

describe_file_systems_blank = {
    "FileSystems": []
}

describe_file_systems_enc_false = {
    "FileSystems": [{
        "FileSystemId": "MyEFS",
        "OwnerId": "Owner12345",
        "CreationToken": 'egCreationToken',
        "CreationTime": '2015-01-01',
        "LifeCycleState": 'available',
        "NumberOfMountTargets": 1,
        "SizeInBytes": {'Value': 123,'Timestamp': '2015-01-01','ValueInIA': 123,'ValueInStandard': 123},
        "PerformanceMode": "generalPurpose",
        "Encrypted": False,
        "Tags": [{'Key': 'EgKey', 'Value': 'EgValue'}]
    }]
}


file_system_policy = {
    "FileSystemId": 'MyEFS',
    "Policy": '{"Version": "2012-10-17", \
    "Id": "ExamplePolicy01", \
    "Statement": [ \
        { "Sid": "ExampleSatement01", \
            "Effect": "Allow", \
            "Principal": { \
                "AWS": "arn:aws:iam::111122223333:user/CarlosSalazar"}, \
            "Action": [                \
                "elasticfilesystem:ClientMount", \
                "elasticfilesystem:ClientWrite"], \
            "Resource": "arn:aws:elasticfilesystem:us-east-2:111122223333:file-system/MyEFS", \
            "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]}'
}


@pytest.fixture(scope="function")
def efs_stubber():
    efs_stubber = Stubber(efs)
    efs_stubber.activate()
    yield efs_stubber
    efs_stubber.deactivate()


def test_efs_encryption_true(efs_stubber):
    efs_stubber.add_response("describe_file_systems", describe_file_systems)
    results = efs_filesys_encryption_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyEFS" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    efs_stubber.assert_no_pending_responses()


def test_efs_encryption_false(efs_stubber):
    efs_stubber.add_response("describe_file_systems", describe_file_systems_enc_false)
    results = efs_filesys_encryption_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyEFS" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    efs_stubber.assert_no_pending_responses()



def test_efs_policy(efs_stubber):
    efs_stubber.add_response("describe_file_systems", describe_file_systems)
    efs_stubber.add_response("describe_file_system_policy", file_system_policy)
    results = efs_filesys_policy_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyEFS" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    efs_stubber.assert_no_pending_responses()


def test_efs_no_policy(efs_stubber):
    efs_stubber.add_response("describe_file_systems", describe_file_systems)
    efs_stubber.add_client_error("describe_file_system_policy", 'FileSystemNotFound')
    results = efs_filesys_policy_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyEFS" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    efs_stubber.assert_no_pending_responses()


def test_efs_no_fs(efs_stubber):
    efs_stubber.add_response("describe_file_systems", describe_file_systems_blank)
    results = efs_filesys_policy_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    assert len(list(results)) == 0
    efs_stubber.assert_no_pending_responses()