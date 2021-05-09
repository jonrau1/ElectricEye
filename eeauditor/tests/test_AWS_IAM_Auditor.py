import datetime
import os
import pytest
import sys

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.AWS_IAM_Auditor import (
    iam_mngd_policy_least_priv_check,
    iam
)


list_policies = {
    'Policies': [
        {
            'PolicyName': 'Policy1234',
            'PolicyId': 'Id1234445555666777888',
            'Arn': 'arn:aws:iam:us-east-2:805574742241:policy1234',
            'DefaultVersionId': 'v1',
        }
    ]
}

get_policy_least_priv = {
    'PolicyVersion': {
        'Document': {
            'Version': '2012-10-17', 
            'Statement': [
                {
                    'Sid': 'LambdaCreateDeletePermission', 
                    'Effect': 'Allow', 
                    'Action': ['lambda:CreateFunction', 'lambda:DeleteFunction', 'lambda:DisableReplication'], 
                    'Resource': ['arn:aws:lambda:*:*:function:*']
                    }, 
                    {
                    'Sid': 'IamPassRolePermission', 
                    'Effect': 'Allow', 
                    'Action': ['iam:PassRole'], 
                    'Resource': ['*'], 
                    'Condition': 
                        {'StringLikeIfExists': 
                            {'iam:PassedToService': 'lambda.amazonaws.com'}}
                    }, 
                    {
                    'Sid': 'CloudFrontListDistributions', 
                    'Effect': 'Allow', 
                    'Action': ['cloudfront:ListDistributionsByLambdaFunction'], 
                    'Resource': ['*']
                    }
            ]
        }
        
    }
}


get_policy_condition = {
    'PolicyVersion': {
        'Document': "{ \
            'Version': '2012-10-17', \
            'Statement': [ \
                    { \
                    'Sid': 'IamPassRolePermission', \
                    'Effect': 'Allow', \
                    'Action': 'iam:*', \
                    'Resource': '*', \
                    'Condition': \
                        {'StringLikeIfExists': \
                            {'iam:PassedToService': 'lambda.amazonaws.com'}}}]}"
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
def iam_stubber():
    iam_stubber = Stubber(iam)
    iam_stubber.activate()
    yield iam_stubber
    iam_stubber.deactivate()


# def test_iam_mngd_policy_least_priv_check(iam_stubber):
#     sqs_stubber.add_response("list_policies", list_policies)
#     sqs_stubber.add_response("get_queue_attributes", get_queue_attributes_response)
#     cloudwatch_stubber.add_response(
#         "get_metric_data", get_metric_data_empty_response, get_metric_data_params
#     )
#     results = sqs_old_message_check(
#         cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
#     )
#     for result in results:
#         if "MyQueue" in result["Id"]:
#             assert result["RecordState"] == "ARCHIVED"
#         else:
#             assert False
#     sqs_stubber.assert_no_pending_responses()


def test_iam_mngd_policy_cond_check(iam_stubber):
    iam_stubber.add_response("list_policies", list_policies)
    iam_stubber.add_response("get_policy_version", get_policy_condition)
    results = iam_mngd_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    iam_stubber.assert_no_pending_responses()

# def test_fail(sqs_stubber, cloudwatch_stubber):
#     sqs_stubber.add_response("list_queues", list_queues_response)
#     sqs_stubber.add_response("get_queue_attributes", get_queue_attributes_response)
#     cloudwatch_stubber.add_response(
#         "get_metric_data", get_metric_data_fail_response, get_metric_data_params
#     )
#     results = sqs_old_message_check(
#         cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
#     )
#     for result in results:
#         if "MyQueue" in result["Id"]:
#             assert result["RecordState"] == "ACTIVE"
#         else:
#             assert False
#     sqs_stubber.assert_no_pending_responses()
#     cloudwatch_stubber.assert_no_pending_responses()


# def test_pass(sqs_stubber, cloudwatch_stubber):
#     sqs_stubber.add_response("list_queues", list_queues_response)
#     sqs_stubber.add_response("get_queue_attributes", get_queue_attributes_response)
#     cloudwatch_stubber.add_response(
#         "get_metric_data", get_metric_data_pass_response, get_metric_data_params
#     )
#     results = sqs_old_message_check(
#         cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
#     )
#     for result in results:
#         if "MyQueue" in result["Id"]:
#             assert result["RecordState"] == "ARCHIVED"
#         else:
#             assert False
#     sqs_stubber.assert_no_pending_responses()
#     cloudwatch_stubber.assert_no_pending_responses()


# def test_encrypted_pass(sqs_stubber): 
#     sqs_stubber.add_response("list_queues", list_queues_response)
#     sqs_stubber.add_response("get_queue_attributes", get_encrypted_queue_attributes_response)
#     results = sqs_queue_encryption_check(
#         cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
#     )
#     for result in results:
#         if "MyQueue" in result["Id"]:
#             assert result["RecordState"] == "ARCHIVED"
#         else:
#             assert False
#     sqs_stubber.assert_no_pending_responses()
    

# def test_encrypted_fail(sqs_stubber): 
#     sqs_stubber.add_response("list_queues", list_queues_response)
#     sqs_stubber.add_response("get_queue_attributes", get_unencrypted_queue_attributes_response)
#     results = sqs_queue_encryption_check(
#         cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
#     )
#     for result in results:
#         if "MyQueue" in result["Id"]:
#             assert result["RecordState"] == "ACTIVE"
#         else:
#             assert False
#     sqs_stubber.assert_no_pending_responses()


# def test_blank_queues(sqs_stubber): 
#     sqs_stubber.add_response("list_queues", list_queues_blank_response)
#     #get queue attributes not required because no queues were returned
#     results = sqs_queue_encryption_check(
#         cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
#     )
#     assert len(list(results)) == 0
#     sqs_stubber.assert_no_pending_responses()


# def test_public_sqs_pass(sqs_stubber): 
#     sqs_stubber.add_response("list_queues", list_queues_response)
#     sqs_stubber.add_response("get_queue_attributes", get_attributes_public_access_response)
#     results = sqs_queue_public_accessibility_check(
#         cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
#     )
#     for result in results:
#         if "MyQueue" in result["Id"]:
#             assert result["RecordState"] == "ARCHIVED"
#         else:
#             assert False
#     sqs_stubber.assert_no_pending_responses()


# def test_public_sqs_with_condition_pass(sqs_stubber): 
#     sqs_stubber.add_response("list_queues", list_queues_response)
#     sqs_stubber.add_response("get_queue_attributes", get_attributes_condition_restricting_access_response)
#     results = sqs_queue_public_accessibility_check(
#         cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
#     )
#     for result in results:
#         if "MyQueue" in result["Id"]:
#             assert result["RecordState"] == "ARCHIVED"
#         else:
#             assert False
#     sqs_stubber.assert_no_pending_responses()


# def test_public_sqs_principal_star_fail(sqs_stubber): 
#     sqs_stubber.add_response("list_queues", list_queues_response)
#     sqs_stubber.add_response("get_queue_attributes", get_attributes_principal_star_response)
#     results = sqs_queue_public_accessibility_check(
#         cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
#     )
#     for result in results:
#         if "MyQueue" in result["Id"]:
#             assert result["RecordState"] == "ACTIVE"
#         else:
#             assert False
#     sqs_stubber.assert_no_pending_responses()
