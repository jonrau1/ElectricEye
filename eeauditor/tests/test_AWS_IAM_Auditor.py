import datetime
import os
import pytest
import sys

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.AWS_IAM_Auditor import (
    iam_mngd_policy_least_priv_check,
    iam_user_policy_least_priv_check,
    iam_group_policy_least_priv_check,
    iam_role_policy_least_priv_check,
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

list_users = {'Users': [
    {'Path': '/',
    'UserName': 'example-user1',
    'UserId': 'AIDFUIOSFJKLDFJLKSJF',
    'Arn': 'arn:aws:iam::805574742241:user/example-user1',
    'CreateDate': datetime.datetime(2020, 9, 3, 11, 23, 13),
    'PasswordLastUsed': datetime.datetime(2021, 5, 9, 1, 25, 1)
        }
    ]
}

list_groups = {'Groups': [
        {
            'Path': '/',
            'GroupName': 'examplegroup',
            'GroupId': 'groupid12345678910',
            'Arn': 'arn:aws:iam::805574742241:group/example-user1',
            'CreateDate': datetime.datetime(2015, 1, 1)
        },
    ]
}

list_roles = {'Roles': [
        {
            'Path': '/',
            'RoleName': 'examplerole',
            'RoleId': 'roleid12345678910',
            'Arn': 'arn:aws:iam::805574742241:role/examplerole',
            'CreateDate': datetime.datetime(2015, 1, 1)
        },
    ]
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

list_user_policies = {'PolicyNames': [
    'example-inline']
}

list_group_policies = {'PolicyNames': [
    'example-inline']
}

list_role_policies = {'PolicyNames': [
    'example-inline']
}

get_user_policy_star_star = {
    'UserName': 'example-user1',
    'PolicyName': 'example-inline',
    'PolicyDocument': '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Effect": "Allow", \
                    "Action": "*", \
                    "Resource": "*" \
                    }]}'
}

get_user_policy_condition = {
    'UserName': 'example-user1',
    'PolicyName': 'example-inline',
    'PolicyDocument': '{ \
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


get_group_policy_action_list_resource = {
    'GroupName': 'examplegroup',
    'PolicyName': 'example-inline',
    'PolicyDocument': '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Effect": "Allow", \
                    "Action": "iam:*", \
                    "Resource": ["arn:aws:lambda:*:*:function:*"] \
                    }]}'
}


get_group_policy_action_star_star = {
    'GroupName': 'examplegroup',
    'PolicyName': 'example-inline',
    'PolicyDocument': '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Effect": "Allow", \
                    "Action": "iam:*", \
                    "Resource": "*" \
                    }]}'
}


get_role_policy_two_statements = {
    'RoleName': 'examplerole',
    'PolicyName': 'example-inline',
    'PolicyDocument': '{ \
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

get_role_policy_list_list_resource = {
    'RoleName': 'examplerole',
    'PolicyName': 'example-inline',
    'PolicyDocument': '{ \
            "Version": "2012-10-17", \
            "Statement": [ \
                    { \
                    "Effect": "Allow", \
                    "Action": ["iam:*", "ec2:DescribeInstances"] \
                    "Resource": ["arn:aws:lambda:*:*:function:*"] \
                    }]}'
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


def test_iam_user_policy_star_star_check(iam_stubber):
    iam_stubber.add_response("list_users", list_users)
    iam_stubber.add_response("list_user_policies", list_user_policies)
    iam_stubber.add_response("get_user_policy", get_user_policy_star_star)

    results = iam_user_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "HIGH"
    iam_stubber.assert_no_pending_responses()


def test_iam_user_policy_condition_check(iam_stubber):
    iam_stubber.add_response("list_users", list_users)
    iam_stubber.add_response("list_user_policies", list_user_policies)
    iam_stubber.add_response("get_user_policy", get_user_policy_condition)

    results = iam_user_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
        assert result["Severity"]["Label"] == "INFORMATIONAL"
    iam_stubber.assert_no_pending_responses()


def test_group_policy_action_star_list_check(iam_stubber):
    iam_stubber.add_response("list_groups", list_groups)
    iam_stubber.add_response("list_group_policies", list_group_policies)
    iam_stubber.add_response("get_group_policy", get_group_policy_action_list_resource)

    results = iam_group_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "LOW"
    iam_stubber.assert_no_pending_responses()


def test_group_policy_action_star_star_check(iam_stubber):
    iam_stubber.add_response("list_groups", list_groups)
    iam_stubber.add_response("list_group_policies", list_group_policies)
    iam_stubber.add_response("get_group_policy", get_group_policy_action_star_star)

    results = iam_group_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "HIGH"
    iam_stubber.assert_no_pending_responses()


def test_role_policy_two_statements_check(iam_stubber):
    iam_stubber.add_response("list_roles", list_roles)
    iam_stubber.add_response("list_role_policies", list_role_policies)
    iam_stubber.add_response("get_role_policy", get_role_policy_two_statements)

    results = iam_role_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "HIGH"
    iam_stubber.assert_no_pending_responses()


def test_role_policy_list_list_resource_check(iam_stubber):
    iam_stubber.add_response("list_roles", list_roles)
    iam_stubber.add_response("list_role_policies", list_role_policies)
    iam_stubber.add_response("get_role_policy", get_role_policy_list_list_resource)

    results = iam_role_policy_least_priv_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "LOW"
    iam_stubber.assert_no_pending_responses()
