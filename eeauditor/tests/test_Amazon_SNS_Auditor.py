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
from auditors.aws.Amazon_SNS_Auditor import (
    sns_cross_account_check,
    sns_http_encryption_check,
    sns_public_access_check,
    sns_topic_encryption_check,
    sns,
)


list_topics_response = {
    "Topics": [{"TopicArn": "arn:aws:sns:us-east-1:012345678901:MyTopic"},],
}

get_topic_attributes_no_AWS = {
    "Attributes": {
        "Policy": '{"Version": "2008-10-17","Id": "__default_policy_ID","Statement": [{"Sid": "__default_statement_ID","Effect": "Allow","Principal": {"AWS": "*"},"Action": ["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish","SNS:Receive"],"Resource": "arn:aws:sns:us-east-1:012345678901:cloudtrail-sns","Condition": {"StringEquals": {"AWS:SourceOwner": "012345678901"}}},{"Sid": "AWSCloudTrailSNSPolicy20150319","Effect": "Allow","Principal": {"Service": "cloudtrail.amazonaws.com"},"Action": "SNS:Publish","Resource": "arn:aws:sns:us-east-1:012345678901:cloudtrail-sns"}]}'
    }
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
        "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::012345678901:root"},"Action":["SNS:Publish","SNS:RemovePermission","SNS:SetTopicAttributes","SNS:DeleteTopic","SNS:ListSubscriptionsByTopic","SNS:GetTopicAttributes","SNS:Receive","SNS:AddPermission","SNS:Subscribe"],"Resource":"arn:aws:sns:us-east-1:012345678901:MyTopic"}]}'
    }
}

get_topic_attributes_response2 = {
    "Attributes": {
        "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1:012345678901:MyTopic","Condition":{"StringEquals":{"AWS:SourceOwner":"012345678901"}}}]}'
    }
}

get_topic_attributes_response3 = {
    "Attributes": {
        "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:Publish","SNS:RemovePermission","SNS:SetTopicAttributes","SNS:DeleteTopic","SNS:ListSubscriptionsByTopic","SNS:GetTopicAttributes","SNS:Receive","SNS:AddPermission","SNS:Subscribe"],"Resource":"arn:aws:sns:us-east-1:012345678901:MyTopic","Condition":{"StringEquals":{"AWS:SourceOwner":"012345678901"}}},{"Sid":"__console_pub_0","Effect":"Allow","Principal":{"AWS":"*"},"Action":"SNS:Publish","Resource":"arn:aws:sns:us-east-1:012345678901:MyTopic"},{"Sid":"__console_sub_0","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:Subscribe","SNS:Receive"],"Resource":"arn:aws:sns:us-east-1:012345678901:MyTopic"}]}'
    }
}


@pytest.fixture(scope="function")
def sns_stubber():
    sns_stubber = Stubber(sns)
    sns_stubber.activate()
    yield sns_stubber
    sns_stubber.deactivate()


def test_id_arn_is_principal(sns_stubber):
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_arn_response)
    results = sns_cross_account_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyTopic" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()


def test_id_is_principal(sns_stubber):
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_only_id_response)
    results = sns_cross_account_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyTopic" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()


def test_id_not_principal(sns_stubber):
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_wrong_id_response)
    results = sns_cross_account_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyTopic" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ACTIVE"
    sns_stubber.assert_no_pending_responses()


def test_no_AWS(sns_stubber):
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_no_AWS)
    results = sns_cross_account_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyTopic" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()


def test_no_access(sns_stubber):
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_response1)
    results = sns_public_access_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyTopic" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()


def test_has_a_condition(sns_stubber):
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_response2)
    results = sns_public_access_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyTopic" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()


def test_has_public_access(sns_stubber):
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_response3)
    results = sns_public_access_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyTopic" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()


def test_no_AWS_Public(sns_stubber):
    sns_stubber.add_response("list_topics", list_topics_response)
    sns_stubber.add_response("get_topic_attributes", get_topic_attributes_no_AWS)
    results = sns_public_access_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyTopic" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sns_stubber.assert_no_pending_responses()
