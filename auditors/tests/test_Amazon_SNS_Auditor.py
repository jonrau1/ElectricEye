import datetime
import os
import pytest
from botocore.stub import Stubber, ANY
from auditors.Amazon_SNS_Auditor import (
    SNSTopicEncryptionCheck,
    SNSHTTPEncryptionCheck,
    SNSPublicAccessCheck,
    SNSCrossAccountCheck,
    sts,
    sns,
)

# not available in local testing without ECS
os.environ["AWS_REGION"] = "us-east-1"
# for local testing, don't assume default profile exists
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

sts_response = {
    "Account": "012345678901",
    "Arn": "arn:aws:iam::012345678901:user/user",
}