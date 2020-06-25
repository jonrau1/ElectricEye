import datetime
import os
import pytest
import sys

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.AWS_Global_Accelerator_Auditor import (
    unhealthy_endpoint_group_check,
    globalaccelerator,
)

list_accelerators_response = {"Accelerators": [{"AcceleratorArn": "MyAcceleratorArn"}]}

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
