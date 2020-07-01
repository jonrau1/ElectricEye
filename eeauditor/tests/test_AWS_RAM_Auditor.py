import datetime
import os
import pytest
import sys

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.AWS_RAM_Auditor import (
    ram_resource_shares_status_check,
    ram_allow_external_principals_check,
    ram,
)

get_resource_shares_pass = {
    "resourceShares": [{"name": "shareName", "status": "ACTIVE"}]
}

get_resource_shares_fail = {
    "resourceShares": [{"name": "shareName", "status": "FAILED"}]
}

get_resource_shares_doesnt_allow_external = {
    "resourceShares": [{"name": "shareName", "allowExternalPrincipals": False}]
}

get_resource_shares_allow_external = {
    "resourceShares": [{"name": "shareName", "allowExternalPrincipals": True}]
}


@pytest.fixture(scope="function")
def ram_stubber():
    ram_stubber = Stubber(ram)
    ram_stubber.activate()
    yield ram_stubber
    ram_stubber.deactivate()


def test_resource_shares_not_fail(ram_stubber):
    ram_stubber.add_response("get_resource_shares", get_resource_shares_pass)
    ram_stubber.add_response("get_resource_shares", get_resource_shares_pass)
    results = ram_resource_shares_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    ram_stubber.assert_no_pending_responses()


def test_resource_shares_fail(ram_stubber):
    ram_stubber.add_response("get_resource_shares", get_resource_shares_fail)
    ram_stubber.add_response("get_resource_shares", get_resource_shares_fail)
    results = ram_resource_shares_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    ram_stubber.assert_no_pending_responses()


def test_share_doesnt_allow_external_principals(ram_stubber):
    ram_stubber.add_response(
        "get_resource_shares", get_resource_shares_doesnt_allow_external
    )
    results = ram_allow_external_principals_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    ram_stubber.assert_no_pending_responses()


def test_share_allows_external_principals(ram_stubber):
    ram_stubber.add_response("get_resource_shares", get_resource_shares_allow_external)
    results = ram_allow_external_principals_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    ram_stubber.assert_no_pending_responses()
