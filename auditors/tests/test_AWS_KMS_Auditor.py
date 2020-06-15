import json
import os
import pytest
from botocore.stub import Stubber, ANY
from auditors.Amazon_kms_Auditor import (
    KMSKeyRotationCheck,
    KMSKeyExposedCheck,
    sts,
    kms,
)

# not available in local testing without ECS
os.environ["AWS_REGION"] = "us-east-1"
# for local testing, don't assume default profile exists
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def sts_stubber():
    sts_stubber = Stubber(sts)
    sts_stubber.activate()
    yield sts_stubber
    sts_stubber.deactivate()


@pytest.fixture(scope="function")
def kms_stubber():
    kms_stubber = Stubber(kms)
    kms_stubber.activate()
    yield kms_stubber
    kms_stubber.deactivate()
