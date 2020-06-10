import datetime
import json
import os
import pytest
from botocore.stub import Stubber, ANY
from auditors.Amazon_SNS_Auditor import (
    SNSTopicEncryptionCheck,
    SNSHTTPEncryptionCheck,
    SNSPublicAccessCheck,
    SNSCrossAccountCheck,
    sts,
    sns,
)

# not available in local testing without ECS
os.environ["AWS_REGION"] = "us-east-1"
# for local testing, don't assume default profile exists
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

sts_response = {
    "Account": "012345678901",
    "Arn": "arn:aws:iam::012345678901:user/user",
}

list_topics_response = {
    "Topics": [{"TopicArn": "arn:aws:sns:us-east-1:012345678901:MyTopic"},],
}

get_topic_attributes_arn_response = {
    "Attributes": {
        "Policy": '{"Statement":[{"Principal":{"AWS":"arn:aws:iam::012345678901:root"},"Condition":{"StringEquals":{"AWS:SourceOwner":"012345678901"}}}]}',
    }
}
get_topic_attributes_only_id_response = {
    "Attributes": {
        "Policy": '{"Statement":[{"Principal":{"AWS":"012345678901"},"Condition":{"StringEquals":{"AWS:SourceOwner":"012345678901"}}}]}',
    }
}

get_topic_attributes_wrong_id_response = {
    "Attributes": {
        "Policy": '{"Statement":[{"Principal":{"AWS":"arn:aws:iam::012345678902:root"},"Condition":{"StringEquals":{"AWS:SourceOwner":"012345678901"}}}]}',
    }
}

get_topic_attributes_response1 = {
    "Attributes": {
        "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::012345678901:root"},"Action":["SNS:Publish","SNS:RemovePermission","SNS:SetTopicAttributes","SNS:DeleteTopic","SNS:ListSubscriptionsByTopic","SNS:GetTopicAttributes","SNS:Receive","SNS:AddPermission","SNS:Subscribe"],"Resource":"arn:aws:sns:us-east-1:012345678901:Test"}]}'
    }
}

get_topic_attributes_response2 = {
    "Attributes": {
        "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1:012345678901:Test","Condition":{"StringEquals":{"AWS:SourceOwner":"012345678901"}}}]}'
    }
}

get_topic_attributes_response3 = {
    "Attributes": {
        "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:Publish","SNS:RemovePermission","SNS:SetTopicAttributes","SNS:DeleteTopic","SNS:ListSubscriptionsByTopic","SNS:GetTopicAttributes","SNS:Receive","SNS:AddPermission","SNS:Subscribe"],"Resource":"arn:aws:sns:us-east-1:012345678901:Test","Condition":{"StringEquals":{"AWS:SourceOwner":"012345678901"}}},{"Sid":"__console_pub_0","Effect":"Allow","Principal":{"AWS":"*"},"Action":"SNS:Publish","Resource":"arn:aws:sns:us-east-1:012345678901:Test"},{"Sid":"__console_sub_0","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:Subscribe","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1:012345678901:Test"}]}'
    }
}


@pytest.fixture(scope="function")
def sts_stubber():
    sts_stubber = Stubber(sts)
    sts_stubber.activate()
    yield sts_stubber
    sts_stubber.deactivate()


@pytest.fixture(scope="function")
def sns_stubber():
    sns_stubber = Stubber(sns)
    sns_stubber.activate()
    yield sns_stubber
    sns_stubber.deactivate()


def test_id_arn_is_principal(sns_stubber, sts_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_arn_response)
    check = SNSCrossAccountCheck()
    results = check.execute()
    for result in results:
        if "MyTopic" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()


def test_id_is_principal(sns_stubber, sts_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response(
        "get_topic_attributes", get_topic_attributes_only_id_response
    )
    check = SNSCrossAccountCheck()
    results = check.execute()
    for result in results:
        if "MyTopic" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()


def test_id_not_principal(sns_stubber, sts_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response(
        "get_topic_attributes", get_topic_attributes_wrong_id_response
    )
    check = SNSCrossAccountCheck()
    results = check.execute()
    for result in results:
        if "MyTopic" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ACTIVE"
    sns_stubber.assert_no_pending_responses()


def test_no_access(sts_stubber, sns_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_response1)
    check = SNSPublicAccessCheck()
    results = check.execute()
    for result in results:
        if "Test" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()


def test_has_a_condition(sts_stubber, sns_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_response2)
    check = SNSPublicAccessCheck()
    results = check.execute()
    for result in results:
        if "Test" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()


def test_has_public_access(sts_stubber, sns_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_response3)
    check = SNSPublicAccessCheck()
    results = check.execute()
    for result in results:
        if "Test" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()
