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
from auditors.aws.Amazon_Kinesis_Analytics_Auditor import (
    kda_log_to_cloudwatch_check,
    kinesisanalyticsv2,
)

list_applications_response = {
    "ApplicationSummaries": [
        {
            "ApplicationName": "AppName",
            "ApplicationARN": "arn",
            "ApplicationStatus": "RUNNING",
            "ApplicationVersionId": 123,
            "RuntimeEnvironment": "FLINK-1_8",
        },
    ],
}

describe_application_response_fail = {
    "ApplicationDetail": {
        "CloudWatchLoggingOptionDescriptions": [],
        "ApplicationName": "AppName",
        "ApplicationARN": "arn",
        "ApplicationStatus": "RUNNING",
        "ApplicationVersionId": 123,
        "RuntimeEnvironment": "FLINK-1_8",
    }
}

describe_application_response_pass = {
    "ApplicationDetail": {
        "CloudWatchLoggingOptionDescriptions": [
            {
                "CloudWatchLoggingOptionId": "string",
                "LogStreamARN": "string",
                "RoleARN": "string",
            },
        ],
        "ApplicationName": "AppName",
        "ApplicationARN": "arn",
        "ApplicationStatus": "RUNNING",
        "ApplicationVersionId": 123,
        "RuntimeEnvironment": "FLINK-1_8",
    }
}


@pytest.fixture(scope="function")
def kinesisanalyticsv2_stubber():
    kinesisanalyticsv2_stubber = Stubber(kinesisanalyticsv2)
    kinesisanalyticsv2_stubber.activate()
    yield kinesisanalyticsv2_stubber
    kinesisanalyticsv2_stubber.deactivate()


def test_no_cloudwatch_logging(kinesisanalyticsv2_stubber):
    kinesisanalyticsv2_stubber.add_response(
        "list_applications", list_applications_response
    )
    kinesisanalyticsv2_stubber.add_response(
        "describe_application", describe_application_response_fail
    )
    results = kda_log_to_cloudwatch_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    kinesisanalyticsv2_stubber.assert_no_pending_responses()


def test_cloudwatch_logging(kinesisanalyticsv2_stubber):
    kinesisanalyticsv2_stubber.add_response(
        "list_applications", list_applications_response
    )
    kinesisanalyticsv2_stubber.add_response(
        "describe_application", describe_application_response_pass
    )
    results = kda_log_to_cloudwatch_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    kinesisanalyticsv2_stubber.assert_no_pending_responses()
