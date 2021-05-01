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
import json

registry = CheckRegister()

# import boto3 clients
codeartifact = boto3.client("codeartifact")


@registry.register_check("codeartifact")
def codeartifact_repo_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = codeartifact.list_repositories()
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    for repo in response["repositories"]:
        domainName = repo['domainName']
        domainOwner = repo['domainOwner']
        repositoryName = repo['name']
        repoArn = repo['arn']

        try: 
            repo_policy = codeartifact.get_repository_permissions_policy(
                domain=domainName,
                domainOwner=domainOwner,
                repository=repositoryName
            )
            policy = json.loads(repo_policy['policy']['document'])
            accessibility = "limited"

            for statement in policy["Statement"]:
                if statement["Effect"] == 'Allow':
                    if statement.get("Principal") == '*' or len([i for i in statement['Principal'].values() if f'arn:aws:iam::{awsAccountId}:root' in i]) > 0: 
                        if statement.get('Condition') == None: 
                            # monitor for Update/Delete repo actions with no principal listed
                            if "PublishPackageVersion" in statement.get('Action') or \
                                "PutRepositoryPermissionsPolicy" in statement.get('Action') or \
                                "UpdateRepository" in statement.get('Action') or \
                                "DeleteRepositoryPermissionsPolicy" in statement.get('Action') or \
                                "DisposePackageVersions" in statement.get('Action'):
                                    accessibility = "not_limited"

                            elif statement.get('Action') == "*" or statement.get('Action') == "codeartifact:*":
                                accessibility = "not_limited"

        except codeartifact.exceptions.ResourceNotFoundException:
            # If no policy is applied, access is repo owner only.
            accessibility = "not_limited"

        if accessibility == "limited":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/codeartifact_repo_policy_check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CodeArtifact.1] CodeArtifact repos should have a resource policy with least privilege applied",
                "Description": f"CodeArtifact repository {repositoryName} has a resource policy with least privilege applied",
                "Remediation": {
                    "Recommendation": {
                        "Text": "CodeArtifact repos should use resource policies to further protect repositories from unauthorized access.  See the CodeArtifact docs for more details",
                        "Url": "https://docs.aws.amazon.com/codeartifact/latest/ug/repo-policies.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeArtifactRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {
                            "name": repositoryName,
                            "domain": domainName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                            "NIST CSF PR.AC-4",
                            "NIST CSF PR.DS-5",
                            "NIST CSF PR.PT-3",
                            "NIST SP 800-53 AC-1"
                            "NIST SP 800-53 AC-3"
                            "NIST SP 800-53 AC-17"
                            "NIST SP 800-53 AC-22"
                            "ISO 27001:2013 A.13.1.2"
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/codeartifact_repo_policy_check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CodeArtifact.1] CodeArtifact repos should have a resource policy with least privilege applied",
                "Description": f"CodeArtifact repository {repositoryName} has a resource policy with least privilege applied",
                "Remediation": {
                    "Recommendation": {
                        "Text": "CodeArtifact repos should use resource policies to further protect repositories from unauthorized access.  See the CodeArtifact docs for more details",
                        "Url": "https://docs.aws.amazon.com/codeartifact/latest/ug/repo-policies.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeArtifactRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {
                            "name": repositoryName,
                            "domain": domainName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                            "NIST CSF PR.AC-4",
                            "NIST CSF PR.DS-5",
                            "NIST CSF PR.PT-3",
                            "NIST SP 800-53 AC-1"
                            "NIST SP 800-53 AC-3"
                            "NIST SP 800-53 AC-17"
                            "NIST SP 800-53 AC-22"
                            "ISO 27001:2013 A.13.1.2"
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding


@registry.register_check("codeartifact")
def codeartifact_domain_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = codeartifact.list_domains()
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    for domain in response["domains"]:
        domainName = domain['name']
        domainOwner = domain['owner']
        status = domain['status']
        domainArn = f"arn:aws:codeartifact:{awsRegion}:{domainOwner}:domain/{domainName}"
        try: 
            domain_policy = codeartifact.get_domain_permissions_policy(
                domain=domainName,
                domainOwner=domainOwner
            )
            policy = json.loads(domain_policy['policy']['document'])
            accessibility = "limited"

            for statement in policy["Statement"]:
                if statement["Effect"] == 'Allow':
                    if statement.get("Principal") == '*' or len([i for i in statement['Principal'].values() if f'arn:aws:iam::{awsAccountId}:root' in i]) > 0: 
                        if statement.get('Condition') == None: 
                            # monitor for Update/Delete actions with no principal listed
                            if "PublishPackageVersion" in statement.get('Action') or \
                                "PutRepositoryPermissionsPolicy" in statement.get('Action') or \
                                "UpdateRepository" in statement.get('Action') or \
                                "DisposePackageVersions" in statement.get('Action') or \
                                "CreateDomain" in statement.get('Action') or \
                                "CreateRepository" in statement.get('Action') or \
                                "DeleteDomain" in statement.get('Action') or \
                                "DeleteDomainPermissionsPolicy" in statement.get('Action') or \
                                "DeleteRepositoryPermissionsPolicy" in statement.get('Action') or \
                                "PutDomainPermissionsPolicy" in statement.get('Action'):
                                    accessibility = "not_limited"

                            elif statement.get('Action') == "*" or statement.get('Action') == "codeartifact:*":
                                accessibility = "not_limited"

        except codeartifact.exceptions.ResourceNotFoundException:
            # If no policy is applied, domain (and underlying repos) are owner only.
            accessibility = "not_limited"

        if accessibility == "limited":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/codeartifact_domain_policy_check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CodeArtifact.2] CodeArtifact domains should have a resource policy with least privilege applied",
                "Description": f"CodeArtifact domain {domainName} has a resource policy with least privilege applied",
                "Remediation": {
                    "Recommendation": {
                        "Text": "CodeArtifact domains should use resource policies to further protect repositories from unauthorized access.  See the CodeArtifact docs for more details",
                        "Url": "https://docs.aws.amazon.com/codeartifact/latest/ug/domain-policies.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeArtifactDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {
                            "name": domainName,
                            "status": status}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                            "NIST CSF PR.AC-4",
                            "NIST CSF PR.DS-5",
                            "NIST CSF PR.PT-3",
                            "NIST SP 800-53 AC-1"
                            "NIST SP 800-53 AC-3"
                            "NIST SP 800-53 AC-17"
                            "NIST SP 800-53 AC-22"
                            "ISO 27001:2013 A.13.1.2"
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": domainArn + "/codeartifact_domain_policy_check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": domainArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CodeArtifact.2] CodeArtifact domains should have a resource policy with least privilege applied",
                "Description": f"CodeArtifact domain {domainName} does not have a resource policy with least privilege applied",
                "Remediation": {
                    "Recommendation": {
                        "Text": "CodeArtifact domains should use resource policies to further protect repositories from unauthorized access.  See the CodeArtifact docs for more details",
                        "Url": "https://docs.aws.amazon.com/codeartifact/latest/ug/domain-policies.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeArtifactDomain",
                        "Id": domainArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {
                            "name": domainName,
                            "status": status}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                            "NIST CSF PR.AC-4",
                            "NIST CSF PR.DS-5",
                            "NIST CSF PR.PT-3",
                            "NIST SP 800-53 AC-1"
                            "NIST SP 800-53 AC-3"
                            "NIST SP 800-53 AC-17"
                            "NIST SP 800-53 AC-22"
                            "ISO 27001:2013 A.13.1.2"
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding