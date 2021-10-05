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

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.Amazon_QLDB_Auditor import qldb_deletion_protection_check, qldb

list_ledgers_response = {
    "Ledgers": [{"Name": "Ledger1"}, {"Name": "Ledger2"},],
}

describe_ledger_response_pass = {"DeletionProtection": True}
describe_ledger_response_fail = {"DeletionProtection": False}


@pytest.fixture(scope="function")
def qldb_stubber():
    qldb_stubber = Stubber(qldb)
    qldb_stubber.activate()
    yield qldb_stubber
    qldb_stubber.deactivate()


def test_deletion_protection_true(qldb_stubber):
    qldb_stubber.add_response("list_ledgers", list_ledgers_response)
    qldb_stubber.add_response("describe_ledger", describe_ledger_response_pass)
    qldb_stubber.add_response("describe_ledger", describe_ledger_response_pass)
    results = qldb_deletion_protection_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    qldb_stubber.assert_no_pending_responses()


def test_deletion_protection_false(qldb_stubber):
    qldb_stubber.add_response("list_ledgers", list_ledgers_response)
    qldb_stubber.add_response("describe_ledger", describe_ledger_response_fail)
    qldb_stubber.add_response("describe_ledger", describe_ledger_response_fail)
    results = qldb_deletion_protection_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    qldb_stubber.assert_no_pending_responses()


def test_deletion_protection_mixed(qldb_stubber):
    qldb_stubber.add_response("list_ledgers", list_ledgers_response)
    qldb_stubber.add_response("describe_ledger", describe_ledger_response_pass)
    qldb_stubber.add_response("describe_ledger", describe_ledger_response_fail)
    results = qldb_deletion_protection_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    count = 1
    for result in results:
        if count:
            assert result["RecordState"] == "ARCHIVED"
            count -= 1
        else:
            assert result["RecordState"] == "ACTIVE"
    qldb_stubber.assert_no_pending_responses()
