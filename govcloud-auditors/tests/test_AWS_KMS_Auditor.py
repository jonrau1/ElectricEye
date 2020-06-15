import datetime
import json
import os
import pytest
from botocore.stub import Stubber, ANY
from auditors.AWS_KMS_Auditor import (
    KMSKeyRotationCheck,
    KMSKeyExposedCheck,
    sts,
    kms,
)

# not available in local testing without ECS
os.environ["AWS_REGION"] = "us-east-1"
# for local testing, don't assume default profile exists
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

sts_response = {
    "Account": "012345678901",
    "Arn": "arn:aws:iam::012345678901:user/user",
}

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
            "KeyArn": "arn:aws:kms:us-east-1:012345678901:key/273e5d8e-4746-4ba9-be3a-4dce36783814"
        }
    ]
}

get_key_rotation_status_response = {
    "KeyRotationEnabled": True
}

get_key_rotation_status_response1 = {
    "KeyRotationEnabled": False
}

@pytest.fixture(scope="function")
def sts_stubber():
    sts_stubber = Stubber(sts)
    sts_stubber.activate()
    yield sts_stubber
    sts_stubber.deactivate()


@pytest.fixture(scope="function")
def kms_stubber():
    kms_stubber = Stubber(kms)
    kms_stubber.activate()
    yield kms_stubber
    kms_stubber.deactivate()


def test_has_public_key(kms_stubber, sts_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    kms_stubber.add_response("list_aliases", list_aliases_response)
    kms_stubber.add_response("get_key_policy", get_key_policy_public_response)
    check = KMSKeyExposedCheck()
    results = check.execute()
    for result in results:
        if "s3" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    kms_stubber.assert_no_pending_responses()


def test_no_public_key(kms_stubber, sts_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    kms_stubber.add_response("list_aliases", list_aliases_response)
    kms_stubber.add_response("get_key_policy", get_key_policy_not_public_response)
    check = KMSKeyExposedCheck()
    results = check.execute()
    for result in results:
        if "s3" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    kms_stubber.assert_no_pending_responses()

def test_key_rotation_enabled(sts_stubber, kms_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    kms_stubber.add_response("list_keys", list_keys_response)
    kms_stubber.add_response("get_key_rotation_status", get_key_rotation_status_response)
    check = KMSKeyRotationCheck()
    results = check.execute()
    for result in results:
        if "273e5d8e-4746-4ba9-be3a-4dce36783814" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    kms_stubber.assert_no_pending_responses()

def test_has_condition(kms_stubber, sts_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    kms_stubber.add_response("list_aliases", list_aliases_response)
    kms_stubber.add_response("get_key_policy", get_key_policy_has_condition_response)
    check = KMSKeyExposedCheck()
    results = check.execute()
    for result in results:
        if "s3" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    kms_stubber.assert_no_pending_responses()

def test_no_AWS(kms_stubber, sts_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    kms_stubber.add_response("list_aliases", list_aliases_response)
    kms_stubber.add_response("get_key_policy", get_key_policy_no_AWS_response)
    check = KMSKeyExposedCheck()
    results = check.execute()
    for result in results:
        if "s3" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    kms_stubber.assert_no_pending_responses()
    
def test_key_rotation_not_enabled(sts_stubber, kms_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    kms_stubber.add_response("list_keys", list_keys_response)
    kms_stubber.add_response("get_key_rotation_status", get_key_rotation_status_response1)
    check = KMSKeyRotationCheck()
    results = check.execute()
    for result in results:
        if "273e5d8e-4746-4ba9-be3a-4dce36783814" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    kms_stubber.assert_no_pending_responses()
