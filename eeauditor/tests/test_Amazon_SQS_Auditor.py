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
