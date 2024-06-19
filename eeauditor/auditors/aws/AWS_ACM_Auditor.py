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
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

def list_certificates(cache, session):
    acm = session.client("acm")
    response = cache.get("list_certificates")
    if response:
        return response
    cache["list_certificates"] = [x["CertificateArn"] for x in acm.list_certificates()['CertificateSummaryList']]
    return cache["list_certificates"]

@registry.register_check("acm")
def certificate_revocation_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ACM.1] ACM Certificates should be monitored for revocation"""
    acm = session.client("acm")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for carn in list_certificates(cache, session):
        # Get ACM Cert Details
        cert = acm.describe_certificate(CertificateArn=carn)["Certificate"]
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cert,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        cDomainName = str(cert['DomainName'])
        cIssuer = str(cert['Issuer'])
        cSerial = str(cert['Serial'])
        cStatus = str(cert['Status'])
        cKeyAlgo = str(cert['KeyAlgorithm'])
        try:
            # this is a failing check
            revokeReason = str(cert['RevocationReason'])
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": carn + "/acm-cert-revoke-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": carn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Denial of Service"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[ACM.1] ACM Certificates should be monitored for revocation",
                "Description": "ACM Certificate "
                + carn
                + " is currently revoked due to "
                + revokeReason
                + ". If the Certificate was in use by any applications they are likely unavailable or returning certificate revocation and invalidity warnings to end-users who are attempting to browse to your applications. You should immediately generate new certificates and distribute them to your applications (CloudFront, ALB Listeners, self-managed web applicaitons) and communicate with clients and other end-users. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on revocation of certificates, review the ACM FAQ on the topic of 'Revoke'",
                        "Url": "https://aws.amazon.com/certificate-manager/faqs/"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Certificate Manager",
                    "AssetComponent": "Certificate"
                },
                "Resources": [
                    {
                        "Type": "AwsCertificateManagerCertificate",
                        "Id": carn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCertificateManagerCertificate": {
                                "DomainName": cDomainName,
                                "Issuer": cIssuer,
                                "Serial": cSerial,
                                "KeyAlgorithm": cKeyAlgo,
                                "Status": cStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        except Exception as e:
            if str(e) == "'RevocationReason'":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": carn + "/acm-cert-revoke-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": carn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Denial of Service"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[ACM.1] ACM Certificates should be monitored for revocation",
                    "Description": "ACM Certificate "
                    + carn
                    + " is not currently revoked.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on revocation of certificates, review the ACM FAQ on the topic of 'Revoke'",
                            "Url": "https://aws.amazon.com/certificate-manager/faqs/"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Security Services",
                        "AssetService": "Amazon Certificate Manager",
                        "AssetComponent": "Certificate"
                    },
                    "Resources": [
                        {
                            "Type": "AwsCertificateManagerCertificate",
                            "Id": carn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsCertificateManagerCertificate": {
                                    "DomainName": cDomainName,
                                    "Issuer": cIssuer,
                                    "Serial": cSerial,
                                    "KeyAlgorithm": cKeyAlgo,
                                    "Status": cStatus
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.MA-1",
                            "NIST SP 800-53 Rev. 4 MA-2",
                            "NIST SP 800-53 Rev. 4 MA-3",
                            "NIST SP 800-53 Rev. 4 MA-5",
                            "NIST SP 800-53 Rev. 4 MA-6",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.11.1.2",
                            "ISO 27001:2013 A.11.2.4",
                            "ISO 27001:2013 A.11.2.5",
                            "ISO 27001:2013 A.11.2.6"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                print(e)

@registry.register_check("acm")
def certificate_in_use_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ACM.2] ACM Certificates should be in use"""
    acm = session.client("acm")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for carn in list_certificates(cache, session):
        # Get ACM Cert Details
        cert = acm.describe_certificate(CertificateArn=carn)["Certificate"]
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cert,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        cDomainName = str(cert['DomainName'])
        cIssuer = str(cert['Issuer'])
        cSerial = str(cert['Serial'])
        cStatus = str(cert['Status'])
        cKeyAlgo = str(cert['KeyAlgorithm'])
        if not cert["InUseBy"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": carn + "/acm-cert-in-use-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": carn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[ACM.2] ACM Certificates should be in use",
                "Description": "ACM Certificate "
                + carn
                + " is currently not in use, this can be indicative of an orphaned certificate or that the downstream workloads are no longer active (maliciously or not). Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on installing certifactes refer to the Services integrated with AWS Certificate Manager section of the AWS Certificate Manager User Guide.",
                        "Url": "https://docs.aws.amazon.com/acm/latest/userguide/acm-services.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Certificate Manager",
                    "AssetComponent": "Certificate"
                },
                "Resources": [
                    {
                        "Type": "AwsCertificateManagerCertificate",
                        "Id": carn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCertificateManagerCertificate": {
                                "DomainName": cDomainName,
                                "Issuer": cIssuer,
                                "Serial": cSerial,
                                "KeyAlgorithm": cKeyAlgo,
                                "Status": cStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": carn + "/acm-cert-in-use-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": carn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ACM.2] ACM Certificates should be in use",
                "Description": "ACM Certificate "
                + carn
                + " is in use.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on installing certifactes refer to the Services integrated with AWS Certificate Manager section of the AWS Certificate Manager User Guide.",
                        "Url": "https://docs.aws.amazon.com/acm/latest/userguide/acm-services.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Certificate Manager",
                    "AssetComponent": "Certificate"
                },
                "Resources": [
                    {
                        "Type": "AwsCertificateManagerCertificate",
                        "Id": carn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCertificateManagerCertificate": {
                                "DomainName": cDomainName,
                                "Issuer": cIssuer,
                                "Serial": cSerial,
                                "KeyAlgorithm": cKeyAlgo,
                                "Status": cStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("acm")
def certificate_transparency_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ACM.3] ACM Certificates should have certificate transparency logs enabled"""
    acm = session.client("acm")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for carn in list_certificates(cache, session):
        # Get ACM Cert Details
        cert = acm.describe_certificate(CertificateArn=carn)["Certificate"]
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cert,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        cDomainName = str(cert['DomainName'])
        cIssuer = str(cert['Issuer'])
        cSerial = str(cert['Serial'])
        cStatus = str(cert['Status'])
        cKeyAlgo = str(cert['KeyAlgorithm'])
        # this is a failing check
        if cert['Options']['CertificateTransparencyLoggingPreference'] == 'DISABLED':
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": carn + "/acm-cert-transparency-log-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": carn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ACM.3] ACM Certificates should have certificate transparency logs enabled",
                "Description": "ACM Certificate "
                + carn
                + " is not using certificate transparency logging. To guard against SSL/TLS certificates that are issued by mistake or by a compromised CA, some browsers require that public certificates issued for your domain be recorded in a certificate transparency log. You should enable it to avoid outages caused to your end-users. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on transparency logging refer to the Services integrated with AWS Certificate Manager section of the AWS Certificate Manager User Guide.",
                        "Url": "https://docs.aws.amazon.com/acm/latest/userguide/acm-services.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Certificate Manager",
                    "AssetComponent": "Certificate"
                },
                "Resources": [
                    {
                        "Type": "AwsCertificateManagerCertificate",
                        "Id": carn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCertificateManagerCertificate": {
                                "DomainName": cDomainName,
                                "Issuer": cIssuer,
                                "Serial": cSerial,
                                "KeyAlgorithm": cKeyAlgo,
                                "Status": cStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": carn + "/acm-cert-transparency-log-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": carn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ACM.3] ACM Certificates should have certificate transparency logs enabled",
                "Description": "ACM Certificate "
                + carn
                + " is using certificate transparency logging.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on transparency logging refer to the Services integrated with AWS Certificate Manager section of the AWS Certificate Manager User Guide.",
                        "Url": "https://docs.aws.amazon.com/acm/latest/userguide/acm-services.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Certificate Manager",
                    "AssetComponent": "Certificate"
                },
                "Resources": [
                    {
                        "Type": "AwsCertificateManagerCertificate",
                        "Id": carn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCertificateManagerCertificate": {
                                "DomainName": cDomainName,
                                "Issuer": cIssuer,
                                "Serial": cSerial,
                                "KeyAlgorithm": cKeyAlgo,
                                "Status": cStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("acm")
def certificate_renewal_status_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ACM.4] ACM Certificates should be renewed successfully"""
    acm = session.client("acm")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

    for carn in list_certificates(cache, session):
        # Get ACM Cert Details
        cert = acm.describe_certificate(CertificateArn=carn)["Certificate"]
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cert,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        cDomainName = str(cert['DomainName'])
        cIssuer = str(cert['Issuer'])
        cSerial = str(cert['Serial'])
        cStatus = str(cert['Status'])
        cKeyAlgo = str(cert['KeyAlgorithm'])
    
        #Will trigger key error if certificate type is not AMAZON_ISSUED
        renewal_status = dict(cert['RenewalSummary']).get('RenewalStatus', '')
        if renewal_status == 'FAILED':
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": carn + "/acm-cert-renewal-status-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": carn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[ACM.4] ACM Certificates should be renewed successfully",
                "Description": f"ACM Certificate {carn} renewal has failed",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on certificate renewals, please refer to the Managed Renewal section of the AWS Certificate Manager User Guide.",
                        "Url": "https://docs.aws.amazon.com/acm/latest/userguide/check-certificate-renewal-status.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Certificate Manager",
                    "AssetComponent": "Certificate"
                },
                "Resources": [
                    {
                        "Type": "AwsCertificateManagerCertificate",
                        "Id": carn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCertificateManagerCertificate": {
                                "DomainName": cDomainName,
                                "Issuer": cIssuer,
                                "Serial": cSerial,
                                "KeyAlgorithm": cKeyAlgo,
                                "Status": cStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        if renewal_status == 'PENDING_VALIDATION':
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": carn + "/acm-cert-renewal-status-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": carn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[ACM.4] ACM Certificates should be renewed successfully",
                "Description": f"ACM Certificate {carn} renewal is pending user validation",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on certificate renewals, please refer to the Managed Renewal section of the AWS Certificate Manager User Guide.",
                        "Url": "https://docs.aws.amazon.com/acm/latest/userguide/check-certificate-renewal-status.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Certificate Manager",
                    "AssetComponent": "Certificate"
                },
                "Resources": [
                    {
                        "Type": "AwsCertificateManagerCertificate",
                        "Id": carn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCertificateManagerCertificate": {
                                "DomainName": cDomainName,
                                "Issuer": cIssuer,
                                "Serial": cSerial,
                                "KeyAlgorithm": cKeyAlgo,
                                "Status": cStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        if renewal_status == 'PENDING_AUTO_RENEWAL' or renewal_status == 'SUCCESS':
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": carn + "/acm-cert-renewal-status-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": carn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ACM.4] ACM Certificates should be renewed successfully",
                "Description": f"ACM Certificate {carn} renewal is in a {str(cert['RenewalSummary']['RenewalStatus'])} state",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on certificate renewals, please refer to the Managed Renewal section of the AWS Certificate Manager User Guide.",
                        "Url": "https://docs.aws.amazon.com/acm/latest/userguide/check-certificate-renewal-status.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Certificate Manager",
                    "AssetComponent": "Certificate"
                },
                "Resources": [
                    {
                        "Type": "AwsCertificateManagerCertificate",
                        "Id": carn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCertificateManagerCertificate": {
                                "DomainName": cDomainName,
                                "Issuer": cIssuer,
                                "Serial": cSerial,
                                "KeyAlgorithm": cKeyAlgo,
                                "Status": cStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("acm")
def certificate_status_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ACM.5] ACM Certificates should be correctly validated"""
    acm = session.client("acm")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for carn in list_certificates(cache, session):
        # Get ACM Cert Details
        cert = acm.describe_certificate(CertificateArn=carn)["Certificate"]
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cert,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        cDomainName = str(cert['DomainName'])
        cIssuer = str(cert['Issuer'])
        cSerial = str(cert['Serial'])
        cStatus = str(cert['Status'])
        cKeyAlgo = str(cert['KeyAlgorithm'])
        # this is a passing check
        if cStatus == 'ISSUED':
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": carn + "/acm-cert-status-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": carn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ACM.5] ACM Certificates should be correctly validated",
                "Description": f"ACM Certificate {carn} is successfully issued",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on certificate issuing, please refer to the Issuing Certificates section of the AWS Certificate Manager User Guide.",
                        "Url": "https://docs.aws.amazon.com/acm/latest/userguide/gs.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Certificate Manager",
                    "AssetComponent": "Certificate"
                },
                "Resources": [
                    {
                        "Type": "AwsCertificateManagerCertificate",
                        "Id": carn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCertificateManagerCertificate": {
                                "DomainName": cDomainName,
                                "Issuer": cIssuer,
                                "Serial": cSerial,
                                "KeyAlgorithm": cKeyAlgo,
                                "Status": cStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        if cStatus == 'EXPIRED' or \
            cStatus == 'VALIDATION_TIMED_OUT' or \
            cStatus == 'REVOKED' or \
            cStatus == 'FAILED':
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": carn + "/acm-cert-renewal-status-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": carn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[ACM.5] ACM Certificates should be correctly validated",
                "Description": f"ACM Certificate {carn} has not been successfully issued.  State: {cStatus}",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on certificate issuing, please refer to the Issuing Certificates section of the AWS Certificate Manager User Guide.",
                        "Url": "https://docs.aws.amazon.com/acm/latest/userguide/gs.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Certificate Manager",
                    "AssetComponent": "Certificate"
                },
                "Resources": [
                    {
                        "Type": "AwsCertificateManagerCertificate",
                        "Id": carn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCertificateManagerCertificate": {
                                "DomainName": cDomainName,
                                "Issuer": cIssuer,
                                "Serial": cSerial,
                                "KeyAlgorithm": cKeyAlgo,
                                "Status": cStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding