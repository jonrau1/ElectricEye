import datetime
import os
import pytest
from botocore.stub import Stubber, ANY
from auditors.AWS_Lambda_Auditor import FunctionUnusedCheck

os.environ["AWS_REGION"] = "us-east-1"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

sts_response = {
    "Account": "012345678901",
    "Arn": "arn:aws:iam::012345678901:user/user",
}

list_functions_response = {
    "Functions": [
        {
            "FunctionName": "lambda-runner",
            "FunctionArn": "arn:aws:lambda:us-east-1:012345678901:function:lambda-runner",
            "LastModified": "2019-05-02T22:00:23.807+0000",
        },
    ],
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
            "Label": "Invocations",
            "Timestamps": [],
            "Values": [],
            "StatusCode": "Complete",
        }
    ],
}

get_metric_data_response = {
    "MetricDataResults": [
        {
            "Id": "m1",
            "Label": "Invocations",
            "Timestamps": [datetime.datetime.now(datetime.timezone.utc)],
            "Values": [3.0,],
            "StatusCode": "Complete",
        }
    ],
}


@pytest.fixture(scope="function")
def sts_stubber():
    sts_stubber = Stubber(FunctionUnusedCheck.sts)
    sts_stubber.activate()
    yield sts_stubber
    sts_stubber.deactivate()


@pytest.fixture(scope="function")
def lambda_stubber():
    lambda_stubber = Stubber(FunctionUnusedCheck.lambda_client)
    lambda_stubber.activate()
    yield lambda_stubber
    lambda_stubber.deactivate()


@pytest.fixture(scope="function")
def cloudwatch_stubber():
    cloudwatch_stubber = Stubber(FunctionUnusedCheck.cloudwatch)
    cloudwatch_stubber.activate()
    yield cloudwatch_stubber
    cloudwatch_stubber.deactivate()


def test_recent_use_lambda(lambda_stubber, cloudwatch_stubber, sts_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    lambda_stubber.add_response("list_functions", list_functions_response)
    cloudwatch_stubber.add_response(
        "get_metric_data", get_metric_data_response, get_metric_data_params
    )
    check = FunctionUnusedCheck()
    results = check.execute()
    for result in results:
        if "lambda-runner" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    lambda_stubber.assert_no_pending_responses()
    cloudwatch_stubber.assert_no_pending_responses()


def test_no_activity_failure(lambda_stubber, cloudwatch_stubber, sts_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    lambda_stubber.add_response("list_functions", list_functions_response)
    cloudwatch_stubber.add_response(
        "get_metric_data", get_metric_data_empty_response, get_metric_data_params
    )
    check = FunctionUnusedCheck()
    results = check.execute()
    for result in results:
        if "lambda-runner" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    lambda_stubber.assert_no_pending_responses()
    cloudwatch_stubber.assert_no_pending_responses()


def test_recently_updated(lambda_stubber, cloudwatch_stubber, sts_stubber):
    sts_stubber.add_response("get_caller_identity", sts_response)
    list_functions_recent_update_response = {
        "Functions": [
            {
                "FunctionName": "lambda-runner",
                "FunctionArn": "arn:aws:lambda:us-east-1:012345678901:function:lambda-runner",
                "LastModified": (
                    datetime.datetime.now(datetime.timezone.utc)
                    - datetime.timedelta(days=1)
                ).isoformat(),
            },
        ],
    }
    lambda_stubber.add_response("list_functions", list_functions_recent_update_response)
    cloudwatch_stubber.add_response(
        "get_metric_data", get_metric_data_empty_response, get_metric_data_params
    )
    check = FunctionUnusedCheck()
    results = check.execute()
    for result in results:
        if "lambda-runner" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    lambda_stubber.assert_no_pending_responses()
    cloudwatch_stubber.assert_no_pending_responses()
