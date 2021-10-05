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
from auditors.aws.Amazon_SQS_Auditor import (
    sqs_old_message_check,
    sqs,
    cloudwatch,
    sqs_queue_encryption_check,
    sqs_queue_public_accessibility_check
)

print(sys.path)

list_queues_response = {
    "QueueUrls": ["https://us-east-2.queue.amazonaws.com/805574742241/MyQueue"]
}

get_queue_attributes_response = {
    "Attributes": {
        "MessageRetentionPeriod": "345600",
        "QueueArn": "arn:aws:sqs:us-east-2:805574742241:MyQueue",
    }
}

get_metric_data_params = {
    "EndTime": ANY,
    "MetricDataQueries": ANY,
    "StartTime": ANY,
}

get_metric_data_empty_response = {
    "MetricDataResults": [
        {
            "Id": "m1",
            "Label": "ApproximateAgeOfOldestMessage",
            "Values": [],
            "StatusCode": "Complete",
        }
    ],
}

get_metric_data_fail_response = {
    "MetricDataResults": [
        {
            "Id": "m1",
            "Label": "ApproximateAgeOfOldestMessage",
            "Values": [345500, 345500, 345500],
            "StatusCode": "Complete",
        }
    ],
}

get_metric_data_pass_response = {
    "MetricDataResults": [
        {
            "Id": "m1",
            "Label": "ApproximateAgeOfOldestMessage",
            "Values": [0, 0, 0, 345500, 345500],
            "StatusCode": "Complete",
        }
    ],
}

get_encrypted_queue_attributes_response = {
    "Attributes": {
        "KmsMasterKeyId": "alias/aws/sqs",
        "QueueArn": "arn:aws:sqs:us-east-2:805574742241:MyQueue",
    }
}

get_unencrypted_queue_attributes_response = {
    "Attributes": {
        "QueueArn": "arn:aws:sqs:us-east-2:805574742241:MyQueue",
    }
}

get_attributes_public_access_response = {
    "Attributes": {
    "QueueArn": "arn:aws:sqs:us-east-2:805574742241:MyQueue", 
    "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID", \
    "Statement": \
        [{"Sid":"__owner_statement", \
        "Effect":"Allow", \
        "Principal": \
        {"AWS":"arn:aws:iam::805574742241:root"}, \
        "Action":"SQS:*", \
        "Resource":"arn:aws:sqs:us-east-2:805574742241:MyQueue"}]}'
        }
    }

get_attributes_condition_restricting_access_response = {
    "Attributes": {
    "QueueArn": "arn:aws:sqs:us-east-2:805574742241:MyQueue", 
    "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID", \
    "Statement": \
        [{"Sid":"__owner_statement", \
        "Effect":"Allow", \
        "Principal": "*", \
        "Action":"SQS:*", \
        "Resource":"arn:aws:sqs:us-east-2:805574742241:MyQueue", \
        "Condition":{ \
            "StringEquals":{ \
                "aws:sourceVpce":"vpce-1a2b3c4d"}}}]}'}
    }

get_attributes_principal_star_response = {
    "Attributes": {
    "QueueArn": "arn:aws:sqs:us-east-2:805574742241:MyQueue", 
    "Policy": '{"Version":"2008-10-17","Id":"__default_policy_ID", \
    "Statement": \
        [{"Sid":"__owner_statement", \
        "Effect":"Allow", \
        "Principal": "*",\
        "Action":"SQS:*", \
        "Resource":"arn:aws:sqs:us-east-2:805574742241:MyQueue"}]}'
        }
    }

list_queues_blank_response = {
    "ResponseMetadata":{
      "RequestId":"aaaa-31a6-5a69-964c-aaaa",
      "HTTPStatusCode":200,
      "HTTPHeaders":{
         "x-amzn-requestid":"aaaa-31a6-5a69-964c-aaaa",
         "date":"Tues, 27 Apr 2021 10:15:01 AEST",
         "content-type":"text/xml",
         "content-length":"340"
      },
      "RetryAttempts":0
   }
}

@pytest.fixture(scope="function")
def sqs_stubber():
    sqs_stubber = Stubber(sqs)
    sqs_stubber.activate()
    yield sqs_stubber
    sqs_stubber.deactivate()


@pytest.fixture(scope="function")
def cloudwatch_stubber():
    cloudwatch_stubber = Stubber(cloudwatch)
    cloudwatch_stubber.activate()
    yield cloudwatch_stubber
    cloudwatch_stubber.deactivate()


def test_no_values(sqs_stubber, cloudwatch_stubber):
    sqs_stubber.add_response("list_queues", list_queues_response)
    sqs_stubber.add_response("get_queue_attributes", get_queue_attributes_response)
    cloudwatch_stubber.add_response(
        "get_metric_data", get_metric_data_empty_response, get_metric_data_params
    )
    results = sqs_old_message_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyQueue" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sqs_stubber.assert_no_pending_responses()
    cloudwatch_stubber.assert_no_pending_responses()


def test_fail(sqs_stubber, cloudwatch_stubber):
    sqs_stubber.add_response("list_queues", list_queues_response)
    sqs_stubber.add_response("get_queue_attributes", get_queue_attributes_response)
    cloudwatch_stubber.add_response(
        "get_metric_data", get_metric_data_fail_response, get_metric_data_params
    )
    results = sqs_old_message_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyQueue" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    sqs_stubber.assert_no_pending_responses()
    cloudwatch_stubber.assert_no_pending_responses()


def test_pass(sqs_stubber, cloudwatch_stubber):
    sqs_stubber.add_response("list_queues", list_queues_response)
    sqs_stubber.add_response("get_queue_attributes", get_queue_attributes_response)
    cloudwatch_stubber.add_response(
        "get_metric_data", get_metric_data_pass_response, get_metric_data_params
    )
    results = sqs_old_message_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyQueue" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sqs_stubber.assert_no_pending_responses()
    cloudwatch_stubber.assert_no_pending_responses()


def test_encrypted_pass(sqs_stubber): 
    sqs_stubber.add_response("list_queues", list_queues_response)
    sqs_stubber.add_response("get_queue_attributes", get_encrypted_queue_attributes_response)
    results = sqs_queue_encryption_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyQueue" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sqs_stubber.assert_no_pending_responses()
    

def test_encrypted_fail(sqs_stubber): 
    sqs_stubber.add_response("list_queues", list_queues_response)
    sqs_stubber.add_response("get_queue_attributes", get_unencrypted_queue_attributes_response)
    results = sqs_queue_encryption_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyQueue" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    sqs_stubber.assert_no_pending_responses()


def test_blank_queues(sqs_stubber): 
    sqs_stubber.add_response("list_queues", list_queues_blank_response)
    #get queue attributes not required because no queues were returned
    results = sqs_queue_encryption_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    assert len(list(results)) == 0
    sqs_stubber.assert_no_pending_responses()


def test_public_sqs_pass(sqs_stubber): 
    sqs_stubber.add_response("list_queues", list_queues_response)
    sqs_stubber.add_response("get_queue_attributes", get_attributes_public_access_response)
    results = sqs_queue_public_accessibility_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyQueue" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sqs_stubber.assert_no_pending_responses()


def test_public_sqs_with_condition_pass(sqs_stubber): 
    sqs_stubber.add_response("list_queues", list_queues_response)
    sqs_stubber.add_response("get_queue_attributes", get_attributes_condition_restricting_access_response)
    results = sqs_queue_public_accessibility_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyQueue" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    sqs_stubber.assert_no_pending_responses()


def test_public_sqs_principal_star_fail(sqs_stubber): 
    sqs_stubber.add_response("list_queues", list_queues_response)
    sqs_stubber.add_response("get_queue_attributes", get_attributes_principal_star_response)
    results = sqs_queue_public_accessibility_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "MyQueue" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    sqs_stubber.assert_no_pending_responses()
