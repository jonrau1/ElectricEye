import datetime
import json
import os
import pytest

from botocore.stub import Stubber, ANY

from . import context
from . import context
from auditors.aws.Amazon_EC2_Auditor import (
    ec2_ami_age_check,
    ec2_ami_status_check,
    ec2
)

describe_instances_response = {
    'Reservations': [
        {
            'Instances': [
                {
                    'AmiLaunchIndex': 123,
                    'ImageId': 'image1234',
                    'InstanceId': 'instanceid1234',
                    'InstanceType': 't1.micro',
                    'KernelId': 'string',
                    'KeyName': 'string',
                    'LaunchTime': datetime.datetime(2021, 1, 1),
                    'Monitoring': {
                        'State': 'disabled'
                    },
                    'SubnetId': 'string',
                    'VpcId': 'string',
                    'BlockDeviceMappings': [
                        {
                            'DeviceName': 'string',
                            'Ebs': {
                                'AttachTime': datetime.datetime(2021, 1, 1),
                                'DeleteOnTermination': True|False,
                                'Status': 'attached',
                                'VolumeId': 'string'
                            }
                        },
                    ],
                },
            ],      
        }
    ]
}

describe_images_response_new = {
    'Images': [
        {
            'CreationDate': '2020-12-30T10:14:02.000Z',
            'ImageId': 'instanceid1234',
            'ImageLocation': 'string',
            'ImageType': 'machine',
            'Public': True,
            'RamdiskId': 'string',
            'State': 'available',
            
        },
    ]
}

describe_images_response_old = {
    'Images': [
        {
            'CreationDate': '2018-12-30T10:14:02.000Z',
            'ImageId': 'instanceid1234',
            'ImageLocation': 'string',
            'ImageType': 'machine',
            'Public': True,
            'RamdiskId': 'string',
            'State': 'available',
            
        },
    ]
}

describe_images_response_avail = {
    'Images': [
        {
            'CreationDate': '2018-12-30T10:14:02.000Z',
            'ImageId': 'instanceid1234',
            'ImageLocation': 'string',
            'ImageType': 'machine',
            'Public': True,
            'RamdiskId': 'string',
            'State': 'available',
            
        },
    ]
}

describe_images_response_failed = {
    'Images': [
        {
            'CreationDate': '2018-12-30T10:14:02.000Z',
            'ImageId': 'instanceid1234',
            'ImageLocation': 'string',
            'ImageType': 'machine',
            'Public': True,
            'RamdiskId': 'string',
            'State': 'failed',
            
        },
    ]
}

describe_images_response_pending = {
    'Images': [
        {
            'CreationDate': '2018-12-30T10:14:02.000Z',
            'ImageId': 'instanceid1234',
            'ImageLocation': 'string',
            'ImageType': 'machine',
            'Public': True,
            'RamdiskId': 'string',
            'State': 'pending',
            
        },
    ]
}

# recently deregistered images may result in an empty response
describe_images_response_dereg = {
    'Images': []
}

@pytest.fixture(scope="function")
def ec2_stubber():
    ec2_stubber = Stubber(ec2)
    ec2_stubber.activate()
    yield ec2_stubber
    ec2_stubber.deactivate()


def test_ami_age_new_check(ec2_stubber):
    ec2_stubber.add_response("describe_instances", describe_instances_response)
    ec2_stubber.add_response("describe_images", describe_images_response_new)
    results = ec2_ami_age_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    ec2_stubber.assert_no_pending_responses()


def test_ami_age_old_check(ec2_stubber):
    ec2_stubber.add_response("describe_instances", describe_instances_response)
    ec2_stubber.add_response("describe_images", describe_images_response_old)
    results = ec2_ami_age_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
    ec2_stubber.assert_no_pending_responses()


def test_ami_age_dereg_check(ec2_stubber):
    ec2_stubber.add_response("describe_instances", describe_instances_response)
    ec2_stubber.add_response("describe_images", describe_images_response_dereg)
    results = ec2_ami_age_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    assert len(list(results)) == 0
    ec2_stubber.assert_no_pending_responses()


def test_ami_status_available_check(ec2_stubber):
    ec2_stubber.add_response("describe_instances", describe_instances_response)
    ec2_stubber.add_response("describe_images", describe_images_response_avail)
    results = ec2_ami_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    ec2_stubber.assert_no_pending_responses()


def test_ami_status_dereg_failed_check(ec2_stubber):
    ec2_stubber.add_response("describe_instances", describe_instances_response)
    ec2_stubber.add_response("describe_images", describe_images_response_failed)
    results = ec2_ami_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["Severity"]["Label"] == "HIGH"
        assert result["RecordState"] == "ACTIVE"
    ec2_stubber.assert_no_pending_responses()

#testing error handling with no return value
def test_ami_status_dereg_no_return_check(ec2_stubber):
    ec2_stubber.add_response("describe_instances", describe_instances_response)
    ec2_stubber.add_response("describe_images", describe_images_response_dereg)
    results = ec2_ami_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "HIGH"
    ec2_stubber.assert_no_pending_responses()


def test_ami_status_pending_check(ec2_stubber):
    ec2_stubber.add_response("describe_instances", describe_instances_response)
    ec2_stubber.add_response("describe_images", describe_images_response_pending)
    results = ec2_ami_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "LOW"
    ec2_stubber.assert_no_pending_responses()