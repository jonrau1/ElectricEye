# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

acm = boto3.client("acm")

acmCerts = []
for c in acm.list_certificates()["CertificateSummaryList"]:
    certArn = str(c["CertificateArn"])
    acmCerts.append(certArn)

@registry.register_check("acm")
def certificate_revocation_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """aaaa"""
    for carn in acmCerts:
        cert = acm.describe_certificate(CertificateArn=carn)["Certificate"]
        print(cert)