import datetime
import os
import pytest
import sys

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.Amazon_Shield_Advanced_Auditor import (
    shield_advanced_subscription_latest_attacks,
    shield
)

get_attacks_from_last_7_days = {
    "AttackSummaries": [ 
        {
            'AttackId': 'ID12345',
            'ResourceArn': 'Arn12345',
            'StartTime': datetime.datetime(2015, 1, 1),
            'EndTime': datetime.datetime(2015, 1, 1),
            'AttackVectors': [
                {
                    'VectorType': 'HTTP_REFLECTION'
                },
            ]
        },]
}

get_attacks_from_last_7_days_none = {
    "AttackSummaries": []
}


@pytest.fixture(scope="function")
def shield_stubber():
    shield_stubber = Stubber(shield)
    shield_stubber.activate()
    yield shield_stubber
    shield_stubber.deactivate()


def test_shield_recent_attacks(shield_stubber):
    shield_stubber.add_response("list_attacks", get_attacks_from_last_7_days)
    results = shield_advanced_subscription_latest_attacks(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    shield_stubber.assert_no_pending_responses()


def test_shield_no_recent_attacks(shield_stubber):
    shield_stubber.add_response("list_attacks", get_attacks_from_last_7_days_none)
    results = shield_advanced_subscription_latest_attacks(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    shield_stubber.assert_no_pending_responses()


def test_shield_region_handling(shield_stubber):
    results = shield_advanced_subscription_latest_attacks(
        cache={}, awsAccountId="012345678901", awsRegion="ap-southeast-2", awsPartition="aws"
    )
    assert len(list(results)) == 0