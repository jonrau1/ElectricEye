import datetime
import json
import os
import pytest

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.AWS_KMS_Auditor import (
    kms_key_exposed_check,
    kms_key_rotation_check,
    kms,
)

list_aliases_response = {
    "Aliases": [
        {
            "AliasArn": "arn:aws:kms:us-east-1:012345678901:alias/aws/s3",
            "TargetKeyId": "c84a8fab-6c42-4b33-ad64-a8e0b0ec0a15",
        },
    ],
}

get_key_policy_public_response = {
    "Policy": '{"Version": "2012-10-17","Id": "KeyPolicy1568312239560","Statement": [{"Sid": "StmtID1672312238115","Effect": "Allow","Principal": {"AWS": "*"},"Action": "kms:*","Resource": "*"}]}'
}

get_key_policy_not_public_response = {
    "Policy": '{"Version": "2012-10-17","Id": "KeyPolicy1568312239560","Statement": [{"Sid": "StmtID1672312238115","Effect": "Allow","Principal": {"AWS": "012345678901"},"Action": "kms:*","Resource": "*"}]}'
}

get_key_policy_has_condition_response = {
    "Policy": '{"Version": "2012-10-17","Id": "KeyPolicy1568312239560","Statement": [{"Sid": "StmtID1672312238115","Effect": "Allow","Principal": {"AWS": "*"},"Action": "kms:*","Resource": "*","Condition": {"StringEquals": {"kms:CallerAccount": "012345678901","kms:ViaService": "sns.us-east-1.amazonaws.com"}}}]}'
}

get_key_policy_no_AWS_response = {
    "Policy": '{"Version": "2012-10-17","Id": "KeyPolicy1568312239560","Statement": [{"Sid": "StmtID1672312238115","Effect": "Allow","Principal": {"Service": "cloudtrail.amazonaws.com"},"Action": "kms:*","Resource": "*","Condition": {"StringEquals": {"kms:CallerAccount": "012345678901","kms:ViaService": "sns.us-east-1.amazonaws.com"}}}]}'
}

list_keys_response = {
    "Keys": [
        {
            "KeyId": "273e5d8e-4746-4ba9-be3a-4dce36783814",
            "KeyArn": "arn:aws:kms:us-east-1:012345678901:key/273e5d8e-4746-4ba9-be3a-4dce36783814",
        }
    ]
}

get_key_rotation_status_response = {"KeyRotationEnabled": True}

get_key_rotation_status_response1 = {"KeyRotationEnabled": False}


@pytest.fixture(scope="function")
def kms_stubber():
    kms_stubber = Stubber(kms)
    kms_stubber.activate()
    yield kms_stubber
    kms_stubber.deactivate()


def test_key_rotation_enabled(kms_stubber):
    kms_stubber.add_response("list_keys", list_keys_response)
    kms_stubber.add_response("get_key_rotation_status", get_key_rotation_status_response)
    results = kms_key_rotation_check(cache={}, awsAccountId="012345678901", awsRegion="us-east-1")
    for result in results:
        assert "273e5d8e-4746-4ba9-be3a-4dce36783814" in result["Id"]
        assert result["RecordState"] == "ARCHIVED"
    kms_stubber.assert_no_pending_responses()


def test_key_rotation_not_enabled(kms_stubber):
    kms_stubber.add_response("list_keys", list_keys_response)
    kms_stubber.add_response("get_key_rotation_status", get_key_rotation_status_response1)
    results = kms_key_rotation_check(cache={}, awsAccountId="012345678901", awsRegion="us-east-1")
    for result in results:
        assert "273e5d8e-4746-4ba9-be3a-4dce36783814" in result["Id"]
        assert result["RecordState"] == "ACTIVE"
    kms_stubber.assert_no_pending_responses()


def test_has_public_key(kms_stubber):
    kms_stubber.add_response("list_aliases", list_aliases_response)
    kms_stubber.add_response("get_key_policy", get_key_policy_public_response)
    results = kms_key_exposed_check(cache={}, awsAccountId="012345678901", awsRegion="us-east-1")
    for result in results:
        assert "s3" in result["Id"]
        assert result["RecordState"] == "ACTIVE"
    kms_stubber.assert_no_pending_responses()


def test_no_public_key(kms_stubber):
    kms_stubber.add_response("list_aliases", list_aliases_response)
    kms_stubber.add_response("get_key_policy", get_key_policy_not_public_response)
    results = kms_key_exposed_check(cache={}, awsAccountId="012345678901", awsRegion="us-east-1")
    for result in results:
        assert "s3" in result["Id"]
        assert result["RecordState"] == "ARCHIVED"
    kms_stubber.assert_no_pending_responses()


def test_has_condition(kms_stubber):
    kms_stubber.add_response("list_aliases", list_aliases_response)
    kms_stubber.add_response("get_key_policy", get_key_policy_has_condition_response)
    results = kms_key_exposed_check(cache={}, awsAccountId="012345678901", awsRegion="us-east-1")
    for result in results:
        assert "s3" in result["Id"]
        assert result["RecordState"] == "ARCHIVED"
    kms_stubber.assert_no_pending_responses()


def test_no_AWS(kms_stubber):
    kms_stubber.add_response("list_aliases", list_aliases_response)
    kms_stubber.add_response("get_key_policy", get_key_policy_no_AWS_response)
    results = kms_key_exposed_check(cache={}, awsAccountId="012345678901", awsRegion="us-east-1")
    for result in results:
        assert "s3" in result["Id"]
        assert result["RecordState"] == "ARCHIVED"
    kms_stubber.assert_no_pending_responses()
