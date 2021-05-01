import datetime
import os
import pytest
import sys

from botocore.stub import Stubber, ANY

from . import context
from auditors.aws.AWS_CodeArtifact_Auditor import (
    codeartifact_repo_policy_check,
    codeartifact
)

list_repositories = {
    "repositories": [
        {
            "name": "npm-store",
            "administratorAccount": "111122223333",
            "domainName": "my-domain",
            "domainOwner": "111122223333",
            "arn": "arn:aws:codeartifact:us-west-2:111122223333:repository/my-domain/npm-store",
            "description": "Provides npm artifacts from npm, Inc."
        }
    ]
}

get_repository_permissions_policy_root_list_star = {
    "policy": {
        "resourceArn": "arn:aws:codeartifact:us-west-2:111122223333:repository/my-domain/npm-store",
        'revision': '1.0',
        "document": '{"Version":"2008-10-17","Id":"__default_policy_ID", \
        "Statement": \
            [{"Sid":"__owner_statement", \
            "Effect":"Allow", \
            "Principal": \
            {"AWS":"arn:aws:iam::111122223333:root"}, \
            "Action":"codeartifact:List*", \
            "Resource":"arn:aws:codeartifact:us-west-2:111122223333:repository/my-domain/npm-store"}]}'
    }
}


get_repository_permissions_policy_root_star = {
    "policy": {
        "resourceArn": "arn:aws:codeartifact:us-west-2:111122223333:repository/my-domain/npm-store",
        'revision': '1.0',
        "document": '{"Version":"2008-10-17","Id":"__default_policy_ID", \
        "Statement": \
            [{"Sid":"__owner_statement", \
            "Effect":"Allow", \
            "Principal": \
            {"AWS":"arn:aws:iam::012345678901:root"}, \
            "Action":"codeartifact:*", \
            "Resource":"arn:aws:codeartifact:us-west-2:111122223333:repository/my-domain/npm-store"}]}'
    }
}

get_repository_permissions_policy_star_update = {
    "policy": {
        "resourceArn": "arn:aws:codeartifact:us-west-2:111122223333:repository/my-domain/npm-store",
        'revision': '1.0',
        "document": '{"Version":"2008-10-17","Id":"__default_policy_ID", \
        "Statement": \
            [{"Sid":"__owner_statement", \
            "Effect":"Allow", \
            "Principal": "*", \
            "Action":"codeartifact:PutRepositoryPermissionsPolicy", \
            "Resource":"arn:aws:codeartifact:us-west-2:111122223333:repository/my-domain/npm-store"}]}'
    }
}

get_repository_permissions_policy_star_star = {
    "policy": {
        "resourceArn": "arn:aws:codeartifact:us-west-2:111122223333:repository/my-domain/npm-store",
        'revision': '1.0',
        "document": '{"Version":"2008-10-17","Id":"__default_policy_ID", \
        "Statement": \
            [{"Sid":"__owner_statement", \
            "Effect":"Allow", \
            "Principal": "*", \
            "Action":"*", \
            "Resource":"arn:aws:codeartifact:us-west-2:111122223333:repository/my-domain/npm-store"}]}'
    }
}

get_repository_permissions_policy_star_star_condition = {
    "policy": {
    "resourceArn": "arn:aws:codeartifact:us-west-2:111122223333:repository/my-domain/npm-store", 
    'revision': '1.0',
    "document": '{"Version":"2008-10-17","Id":"__default_policy_ID", \
    "Statement": \
        [{"Sid":"__owner_statement", \
        "Effect":"Allow", \
        "Principal": "*", \
        "Action":"*", \
        "Resource":"*", \
        "Condition":{ \
            "StringEquals":{ \
                "aws:sourceVpce":"vpce-1a2b3c4d"}}}]}'}
    }


@pytest.fixture(scope="function")
def codeartifact_stubber():
    codeartifact_stubber = Stubber(codeartifact)
    codeartifact_stubber.activate()
    yield codeartifact_stubber
    codeartifact_stubber.deactivate()


def test_policy_star_list(codeartifact_stubber):
    codeartifact_stubber.add_response("list_repositories", list_repositories)
    codeartifact_stubber.add_response("get_repository_permissions_policy", get_repository_permissions_policy_root_list_star)
    results = codeartifact_repo_policy_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "npm-store" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    codeartifact_stubber.assert_no_pending_responses()


def test_policy_root_user(codeartifact_stubber):
    codeartifact_stubber.add_response("list_repositories", list_repositories)
    codeartifact_stubber.add_response("get_repository_permissions_policy", get_repository_permissions_policy_root_star)
    results = codeartifact_repo_policy_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "npm-store" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    codeartifact_stubber.assert_no_pending_responses()


def test_policy_star_update(codeartifact_stubber):
    codeartifact_stubber.add_response("list_repositories", list_repositories)
    codeartifact_stubber.add_response("get_repository_permissions_policy", get_repository_permissions_policy_star_update)
    results = codeartifact_repo_policy_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "npm-store" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    codeartifact_stubber.assert_no_pending_responses()


def test_policy_star_star(codeartifact_stubber):
    codeartifact_stubber.add_response("list_repositories", list_repositories)
    codeartifact_stubber.add_response("get_repository_permissions_policy", get_repository_permissions_policy_star_star)
    results = codeartifact_repo_policy_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "npm-store" in result["Id"]:
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    codeartifact_stubber.assert_no_pending_responses()


def test_policy_star_star_condition(codeartifact_stubber):
    codeartifact_stubber.add_response("list_repositories", list_repositories)
    codeartifact_stubber.add_response("get_repository_permissions_policy", get_repository_permissions_policy_star_star_condition)
    results = codeartifact_repo_policy_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "npm-store" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    codeartifact_stubber.assert_no_pending_responses()


def test_policy_no_policy(codeartifact_stubber):
    codeartifact_stubber.add_response("list_repositories", list_repositories)
    codeartifact_stubber.add_client_error("get_repository_permissions_policy", "ResourceNotFoundException")
    results = codeartifact_repo_policy_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        if "npm-store" in result["Id"]:
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    codeartifact_stubber.assert_no_pending_responses()