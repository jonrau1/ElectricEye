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

# import boto3 clients
codeartifact = boto3.client("codeartifact")


@registry.register_check("codeartifact")
def codeartifact_repo_iam_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = codeartifact.list_repositories()
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    for repo in response["repositories"]:
        domainName = repo['domainName']
        domainOwner = repo['domainOwner']
        repositoryName = repo['Name']
        repoArn = repo['arn']

        repo_policy = codeartifact.get_repository_permissions_policy(
            domain=domainName,
            domainOwner=domainOwner,
            repository=repositoryName
        )
        policy = json.loads(repo_policy)
        accessibility = "limited"

        for statement in policy["Statement"]:
            if statement["Effect"] == 'Allow':
                if statement.get("Principal") == '*':
                    if statement.get('Condition') == None: 
                        accessibility = "not_limited"

                    # monitor for Update/Delete repo actions with no specified principal
                    elif statement.get('Action') == "*" or "PublishPackageVersion", "PutRepositoryPermissionsPolicy", 
                        "UpdateRepository", "DisposePackageVersions" in statement.get('Action'):
                         accessibility = "not_limited"

        if accessibility == "limited":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": appArn + "/codeartifact_repo_iam_check",
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
        
        elif accessibility == "limited":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": appArn + "/codeartifact_repo_iam_check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
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