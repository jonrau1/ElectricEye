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
from auditors.aws.AWS_ACM_Auditor import (
    certificate_status_check,
    certificate_renewal_status_check,
    acm
)

list_certificates_response = {
    'CertificateSummaryList': [
        {
            'CertificateArn': 'arn:aws:acm:region:123456789012:certificate/cert1234',
            'DomainName': 'string'
        },
    ]
}

describe_issued_cert_response = {
    'Certificate': {
        'CertificateArn': 'arn:aws:acm:region:123456789012:certificate/cert1234',
        'DomainName': 'string',
        'Serial': 'string',
        'Subject': 'string',
        'Issuer': 'string',
        'Status': 'ISSUED',
        'Type': 'AMAZON_ISSUED',
        'KeyAlgorithm': 'RSA_2048',
        'RenewalSummary': {
            'RenewalStatus': 'SUCCESS',
            'DomainValidationOptions': [{
                'DomainName': 'string',
                'ValidationDomain': 'string',
                'ValidationMethod': 'DNS',

            }],
            'UpdatedAt': datetime.datetime(2015, 1, 1),
        },
    }
}

describe_pending_val_cert_response = {
    'Certificate': {
        'CertificateArn': 'arn:aws:acm:region:123456789012:certificate/cert1234',
        'DomainName': 'string',
        'Serial': 'string',
        'Subject': 'string',
        'Issuer': 'string',
        'Status': 'PENDING_VALIDATION',
        'Type': 'AMAZON_ISSUED',
        'KeyAlgorithm': 'RSA_2048',
        'RenewalSummary': {
            'RenewalStatus': 'PENDING_VALIDATION',
            'DomainValidationOptions': [{
                'DomainName': 'string',
                'ValidationDomain': 'string',
                'ValidationMethod': 'DNS',

            }],
            'UpdatedAt': datetime.datetime(2015, 1, 1),
        },
    }
}

describe_failed_cert_response = {
    'Certificate': {
        'CertificateArn': 'arn:aws:acm:region:123456789012:certificate/cert1234',
        'DomainName': 'string',
        'Serial': 'string',
        'Subject': 'string',
        'Issuer': 'string',
        'Status': 'FAILED',
        'Type': 'AMAZON_ISSUED',
        'KeyAlgorithm': 'RSA_2048',
        'RenewalSummary': {
            'RenewalStatus': 'FAILED',
            'DomainValidationOptions': [{
                'DomainName': 'string',
                'ValidationDomain': 'string',
                'ValidationMethod': 'DNS',

            }],
            'UpdatedAt': datetime.datetime(2015, 1, 1),
        },
    }
}

describe_not_aws_cert_response = {
    'Certificate': {
        'CertificateArn': 'arn:aws:acm:region:123456789012:certificate/cert1234',
        'DomainName': 'string',
        'Serial': 'string',
        'Subject': 'string',
        'Issuer': 'string',
        'Status': 'REVOKED',
        'Type': 'IMPORTED',
        'KeyAlgorithm': 'RSA_2048',
    }
}

@pytest.fixture(scope="function")
def acm_stubber():
    acm_stubber = Stubber(acm)
    acm_stubber.activate()
    yield acm_stubber
    acm_stubber.deactivate()


def test_acm_renewal_status_issued_check(acm_stubber):
    acm_stubber.add_response("list_certificates", list_certificates_response)
    acm_stubber.add_response("describe_certificate", describe_issued_cert_response)
    results = certificate_renewal_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    acm_stubber.assert_no_pending_responses()


def test_acm_renewal_status_pending_validation_check(acm_stubber):
    acm_stubber.add_response("list_certificates", list_certificates_response)
    acm_stubber.add_response("describe_certificate", describe_pending_val_cert_response)
    results = certificate_renewal_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "LOW"
    acm_stubber.assert_no_pending_responses()


def test_acm_renewal_status_failed_check(acm_stubber):
    acm_stubber.add_response("list_certificates", list_certificates_response)
    acm_stubber.add_response("describe_certificate", describe_failed_cert_response)
    results = certificate_renewal_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "HIGH"
    acm_stubber.assert_no_pending_responses()


def test_acm_renewal_status_not_amazon_check(acm_stubber):
    acm_stubber.add_response("list_certificates", list_certificates_response)
    acm_stubber.add_response("describe_certificate", describe_not_aws_cert_response)
    results = certificate_renewal_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    assert len(list(results)) == 0
    acm_stubber.assert_no_pending_responses()


def test_acm_cert_status_issued_check(acm_stubber):
    acm_stubber.add_response("list_certificates", list_certificates_response)
    acm_stubber.add_response("describe_certificate", describe_issued_cert_response)
    results = certificate_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ARCHIVED"
    acm_stubber.assert_no_pending_responses()


def test_acm_cert_status_pending_validation_check(acm_stubber):
    acm_stubber.add_response("list_certificates", list_certificates_response)
    acm_stubber.add_response("describe_certificate", describe_pending_val_cert_response)
    results = certificate_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    assert len(list(results)) == 0
    acm_stubber.assert_no_pending_responses()


def test_acm_renewal_status_failed_check(acm_stubber):
    acm_stubber.add_response("list_certificates", list_certificates_response)
    acm_stubber.add_response("describe_certificate", describe_failed_cert_response)
    results = certificate_status_check(
        cache={}, awsAccountId="012345678901", awsRegion="us-east-1", awsPartition="aws"
    )
    for result in results:
        assert result["RecordState"] == "ACTIVE"
        assert result["Severity"]["Label"] == "HIGH"
    acm_stubber.assert_no_pending_responses()