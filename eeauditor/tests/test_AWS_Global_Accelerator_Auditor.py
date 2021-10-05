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
from auditors.aws.AWS_Global_Accelerator_Auditor import (
    unhealthy_endpoint_group_check,
    flow_logs_enabled_check,
    globalaccelerator,
)

list_accelerators_response = {
    "Accelerators": [{"AcceleratorArn": "MyAcceleratorArn", "Name": "accleratorName"}]
}

list_listeners_response = {"Listeners": [{"ListenerArn": "listenerarn"}]}

list_endpoint_groups_healthy_response = {
    "EndpointGroups": [
        {
            "EndpointDescriptions": [
                {"EndpointId": "endpoint", "HealthState": "HEALTHY"},
            ],
        },
    ],
}

list_endpoint_groups_unhealthy_response = {
    "EndpointGroups": [
        {
            "EndpointDescriptions": [
                {"EndpointId": "endpoint", "HealthState": "UNHEALTHY"},
            ],
        },
    ],
}

describe_accelerator_attributes_pass = {
    "AcceleratorAttributes": {"FlowLogsEnabled": True}
}

describe_accelerator_attributes_fail = {
    "AcceleratorAttributes": {"FlowLogsEnabled": False}
}


@pytest.fixture(scope="function")
def globalaccelerator_stubber():
    globalaccelerator_stubber = Stubber(globalaccelerator)
    globalaccelerator_stubber.activate()
    yield globalaccelerator_stubber
    globalaccelerator_stubber.deactivate()


def test_healthy(globalaccelerator_stubber):
    globalaccelerator_stubber.add_response(
        "list_accelerators", list_accelerators_response
    )
    globalaccelerator_stubber.add_response("list_listeners", list_listeners_response)
    globalaccelerator_stubber.add_response(
        "list_endpoint_groups", list_endpoint_groups_healthy_response
    )
    results = unhealthy_endpoint_group_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    globalaccelerator_stubber.assert_no_pending_responses()


def test_unhealthy(globalaccelerator_stubber):
    globalaccelerator_stubber.add_response(
        "list_accelerators", list_accelerators_response
    )
    globalaccelerator_stubber.add_response("list_listeners", list_listeners_response)
    globalaccelerator_stubber.add_response(
        "list_endpoint_groups", list_endpoint_groups_unhealthy_response
    )
    results = unhealthy_endpoint_group_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    globalaccelerator_stubber.assert_no_pending_responses()


def test_enabled_logs(globalaccelerator_stubber):
    globalaccelerator_stubber.add_response(
        "list_accelerators", list_accelerators_response
    )
    globalaccelerator_stubber.add_response(
        "describe_accelerator_attributes", describe_accelerator_attributes_pass
    )
    results = flow_logs_enabled_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    globalaccelerator_stubber.assert_no_pending_responses()


def test_not_enabled_logs(globalaccelerator_stubber):
    globalaccelerator_stubber.add_response(
        "list_accelerators", list_accelerators_response
    )
    globalaccelerator_stubber.add_response(
        "describe_accelerator_attributes", describe_accelerator_attributes_fail
    )
    results = flow_logs_enabled_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    globalaccelerator_stubber.assert_no_pending_responses()
