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
    "PolicyVersion": {
        "Document": '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Sid": "IamPassRolePermission", \
                    "Effect": "Allow", \
                    "Action": "iam:*", \
                    "Resource": "*", \
                    "Condition": \
                        {"StringLikeIfExists": \
                            {"iam:PassedToService": "lambda.amazonaws.com"}}}]}'
    }
}

get_policy_star_star = {
    "PolicyVersion": {
        "Document": '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Effect": "Allow", \
                    "Action": "*", \
                    "Resource": "*" \
                    }]}'
    }
}

get_policy_action_star_star = {
    "PolicyVersion": {
        "Document": '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Effect": "Allow", \
                    "Action": "iam:*", \
                    "Resource": "*" \
                    }]}'
    }
}

get_policy_action_star_resource = {
    "PolicyVersion": {
        "Document": '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Effect": "Allow", \
                    "Action": "iam:*", \
                    "Resource": ["arn:aws:lambda:*:*:function:*"] \
                    }]}'
    }
}

get_policy_action_resource = {
    "PolicyVersion": {
        "Document": '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Effect": "Allow", \
                    "Action": ["iam:ListRoles", "ec2:DescribeInstances"], \
                    "Resource": ["arn:aws:lambda:*:*:function:*"] \
                    }]}'
    }
}

get_policy_two_statements = {
    "PolicyVersion": {
        "Document": '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Effect": "Allow", \
                    "Action": "*", \
                    "Resource": "*" \
                    }, \
                    { \
                    "Effect": "Allow", \
                    "Action": ["iam:ListRoles", "ec2:DescribeInstances"], \
                    "Resource": ["arn:aws:lambda:*:*:function:*"] \
                    } \
                    ]}'
    }
}

get_policy_action_list_resource = {
    "PolicyVersion": {
        "Document": '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Effect": "Allow", \
                    "Action": ["iam:*", "ec2:DescribeInstances"] \
                    "Resource": ["arn:aws:lambda:*:*:function:*"] \
                    }]}'
    }
}


@pytest.fixture(scope="function")
def iam_stubber():
    iam_stubber = Stubber(iam)
    iam_stubber.activate()
    yield iam_stubber
    iam_stubber.deactivate()

def test_iam_mngd_policy_cond_check(iam_stubber):
    iam_stubber.add_response("list_policies", list_policies)
    iam_stubber.add_response("get_policy_version", get_policy_condition)
    results = iam_mngd_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    iam_stubber.assert_no_pending_responses()


def test_iam_mngd_policy_star_star_check(iam_stubber):
    iam_stubber.add_response("list_policies", list_policies)
    iam_stubber.add_response("get_policy_version", get_policy_star_star)
    results = iam_mngd_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "HIGH"
    iam_stubber.assert_no_pending_responses()


def test_iam_mngd_policy_action_star_star_check(iam_stubber):
    iam_stubber.add_response("list_policies", list_policies)
    iam_stubber.add_response("get_policy_version", get_policy_action_star_star)
    results = iam_mngd_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "HIGH"
    iam_stubber.assert_no_pending_responses()


def test_iam_mngd_policy_action_star_resource_check(iam_stubber):
    iam_stubber.add_response("list_policies", list_policies)
    iam_stubber.add_response("get_policy_version", get_policy_action_star_resource)
    results = iam_mngd_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "LOW"
    iam_stubber.assert_no_pending_responses()


def test_iam_mngd_policy_action_resource_check(iam_stubber):
    iam_stubber.add_response("list_policies", list_policies)
    iam_stubber.add_response("get_policy_version", get_policy_action_resource)
    results = iam_mngd_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
        assert result["Severity"]["Label"] == "INFORMATIONAL"
    iam_stubber.assert_no_pending_responses()


def test_iam_mngd_policy_two_statements_check(iam_stubber):
    iam_stubber.add_response("list_policies", list_policies)
    iam_stubber.add_response("get_policy_version", get_policy_two_statements)
    results = iam_mngd_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "HIGH"
    iam_stubber.assert_no_pending_responses()


def test_iam_mngd_policy_action_star_list_check(iam_stubber):
    iam_stubber.add_response("list_policies", list_policies)
    iam_stubber.add_response("get_policy_version", get_policy_action_list_resource)
    results = iam_mngd_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "LOW"
    iam_stubber.assert_no_pending_responses()