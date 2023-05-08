## Developer Guide

This section is dedicated to guidance around creating new ElectricEye Auditors, it includes naming considerations, required information to map to the [Amazon Security Finding Format (ASFF)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) as well as information that is custom to ElectricEye.

ElectricEye abides by PEP8 and uses `black` for syntax verification, the following considerations must be ***globally*** followed:

> - Use Double Quotes (`""`), Single Quotes are permitted within strings such as the `Description` filed of ASFF.

> - Environment variables should be referenced with `os.environ` in all caps and set as Constants when required, e.g., `SNOW_INSTANCE_NAME = os.environ["SNOW_INSTANCE_NAME"]` within the ServiceNow SSPM Auditors.

> - Regular variables should be in `camelCase` such as `sysPropCache` or `propFinder`.

> - Key and Value pairs should be in `PascalCase` such as `"ProductName": "ElectricEye"`.

> - Function names should be in `snake_case` such as `def servicenow_sspm_downloadable_mime_types_check(...)`.

**Do not forget** to update the tables within the [**Supported Services and Checks** section of the main docs!](README.md#supported-services-and-checks). You can use [Markdown Tables generator](https://www.tablesgenerator.com/markdown_tables) by copying and pasting the current table into the website's UI (underneath the `File/Paste table data...` dropdown menu) and remove the whitespace / added columns for this task.

### Table of Contents

- [Naming an Auditor](#naming-an-auditor)
- [Necessary Imports and License file](#necessary-imports-and-license-file)
- [Creating Caches](#creating-caches)
- [Registering and Defining Checks](#registering-and-defining-checks)
- [Formatting Findings](#formatting-findings)
- [Creating Test](#creating-tests)
- [Auditor testing](#auditor-testing)

### Naming an Auditor

To keep naming consistent, the following pattern of `{Provider}_{ServiceName}_Auditor.py` is used such as [`Amazon_APIGW_Auditor.py`](./eeauditor/auditors/aws/Amazon_APIGW_Auditor.py) or [`GCP_CloudSQL_Auditor.py`](./eeauditor/auditors/gcp/GCP_CloudSQL_Auditor.py). Take notice that some Amazon Web Services (AWS) Cloud services take on the AWS moniker such as [`AWS_MemoryDB_Auditor.py`](./eeauditor/auditors/aws/AWS_MemoryDB_Auditor.py) and should reflect that naming convention, refer the official AWS documentation to verify those cases.

There are some cases where a more generic name is permitted for special-purpose Auditors such as those that use Shodan.io or `detect-secrets` for Secrets Management. In those cases, the Auditor should be named as `{Provider}_{SpecialPurpose}_Auditor.py` such as `Amazon_Shodan_Auditor.py`.

In the case of SaaS Security Posture Management (SSPM) Auditors, the "service name" may not be clearly definable, and best efforts should be made. For instance, the ServiceNow SSPM Auditor that inspects ServiceNow Users is named `Servicenow_Users_Auditor.py` and the rest of the Auditors follow a naming convention that align to the section headers of the ServiceNow Security Best Practice documentation such as `Servicenow_SecureCommunications_Auditor.py` which is dedicated to checking Plugins and System Properties that align to "Secure Communications" settings such as using TLSv1.2, enforcing HTTPS, and so on.

In other cases for SSPM, instead of a service name or "category" you can point to a higher-level product, such as in Microsoft M365 there are multiple product lines such as **Microsoft Defender for Cloud Apps** or **Microsoft Defender for Endpoint**.

### Necessary Imports and License file

Within every single Auditor file, the first contents should be the Apache-2.0 license header

```python
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
```

Next, ensure that necessary libraries are imported into global space and not within specific functions, additionally instantiate the `CheckRegister()`, at the very least you must include the following imports

```python
import datetime
from check_register import CheckRegister

registry = CheckRegister()
```

Only use the minimum necessary amount of imports per Auditor and do not forget to update [`requirements.txt`](./requirements.txt) if libraries outside of the Python core libraries need to be added. ServiceNow uses `pysnow`, GCP uses `googleapiclient.discovery` (installed via [`google-api-python-client`](https://github.com/googleapis/google-api-python-client)) and so on. For instances where there is not a first-party (or even third-party) Python SDK or Client, default to using Python `requests` to wrap the APIs.

In the case of Amazon, `boto3` ***DOES NOT NEED TO BE IMPORTED*** into the Auditors, as it is imported into the Controller and passed to the AWS Auditors. This is done to utilize the `Boto3.Session()` object for overriding Regions, Accounts, and Profiles (as needed).

### Creating Caches

ElectricEye uses locally instantiated Caches using Python `dict` which is invoked per-Auditor, this is done to call a service API only the maximum amount of times required and the response is saved into the `cache` dictionary and retrieved upon subsequent Checks within the Auditor. Use your discretion here and add as many Cache functions as are required for your Auditor. Name your functions either after the exact `method` from the Client API or give it a descriptive name that tells its purpose. The arguments should always be `cache` followed by service-specific values.

AWS requires exactly two arguments for its Caching functions, `cache` and `session` which is passed to `eeauditor.py` via `controller.py`. This `session` is used in place of a `boto3.client` or `boto3.resource`. For example, the following Cache is from the [`Amazon_SNS_Auditor.py`](./eeauditor/auditors/aws/Amazon_SNS_Auditor.py) which uses the `session` object to retrieve a list of [SNS Topics](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns/client/list_topics.html).

```python
def list_topics(cache, session):
    imagebuilder = session.client("imagebuilder")
    response = cache.get("list_topics")
    if response:
        return response
    cache["list_topics"] = sns.list_topics()
    return cache["list_topics"]
```

Generally, the structure of a Cache follows the same order: instantiate whichever CSP or SaaS provider SDK client is required, and then use the Python dictionary [`get()` method](https://www.w3schools.com/python/ref_dictionary_get.asp) to attempt to retrieve the Key within the Cache. For naming simplicity, this Key should match the name of your function, in the above example `list_topics` is used as that is what the Boto3 SNS client method is called.

Use `if` to check if a response is provided from `get()`, by default Python returns a `None` type when the keyname is not found within the dictionary. If there is a response, simply `return` it, if not that is where your Cache-specific business logic is implemented.

**Important Note**: Always take care to remember the schema of the object you will be inserting into the Cache dictionary, as you will likely be looping these values in subsequent Checks that call the Cache within your Auditor.

Once you business logic & parsing is completed, set the keyname in the Cache and then `return` the Cache object to the calling function. In the above example, this is demonstrated by `cache["list_topics"] = sns.list_topics()` and `return cache["list_topics"]`, respectively.

When possible, use a Python SDK's native pagination methods or implement one on your own, take care to research the upstream provider's response size limits, next-key tokenization, retry limits, and implement exponential backoff as required.

Within AWS, **Paginators** are a native `boto3` construct and should be used along with **Filters** to scope-down any responses, the following example shows how a Paginator is used by [`Amazon_EC2_Auditor.py`](./eeauditor/auditors/aws/Amazon_EC2_Auditor.py) alongside Filters.

```python
def paginate(cache, session):
    ec2 = session.client("ec2")
    response = cache.get("paginate")
    if response:
        return response
    get_paginators = ec2.get_paginator("describe_instances")
    if get_paginators:
        cache["paginate"] = get_paginators.paginate(Filters=[{'Name': 'instance-state-name','Values': ['running','stopped']}])
        return cache["paginate"]
```

The above example retruns the entire responder from the Paginator and is handled by downstream functions, you can use `for` loops to further parse down the schema of the response. The above example uses Filters to only retrieve `running` and `stopped` EC2 instances as any other state is transitory and will result in errors. Always test these edge cases when creating Caches and Auditors.

This below example is the Cache for a Google Cloud Platform (GCP) Auditor for CloudSQL instances ([`GCP_CloudSQL_Auditor.py`](./eeauditor/auditors/gcp/GCP_CloudSQL_Auditor.py)), note that the GCP Python Client SDK is imported in Global space. GCP checks are a bit more complicated as the per-service API implementations all widely vary.

```python
...
import googleapiclient.discovery

registry = CheckRegister()

def get_cloudsql_dbs(cache: dict, gcpProjectId: str):
    """
    AggregatedList result provides Zone information as well as every single Instance in a Project
    """
    response = cache.get("get_cloudsql_dbs")
    if response:
        return response

    #  CloudSQL requires SQL Admin API - also doesnt need an aggregatedList
    service = googleapiclient.discovery.build('sqladmin', 'v1beta4')
    instances = service.instances().list(project=gcpProjectId).execute()
    
    cache["get_cloudsql_dbs"] = instances["items"]

    return cache["get_cloudsql_dbs"]
```

For GCP Auditors, the Arguments must be (`cache`, `gcpProjectId`), the implementer decided to declare the `type` which is optional. Note that when the Cache object is set, a specific key is specified to avoid an extra `for` loop, e.g., `cache["get_cloudsql_dbs"] = instances["items"]`

In the next example, a Cache function for an Auditor for ServiceNow ([`Servicenow_Attachments_Auditor.py`](./eeauditor/auditors/servicenow/Servicenow_Attachments_Auditor.py)) is provided which retrieves all `sys_properties` using the `pysnow` SDK. Note the **Constants** that are located in global space which are derived from enviornment variables which are parsed and provided from the Controller.

```python
import datetime
import pysnow
import os
from check_register import CheckRegister

registry = CheckRegister()

SNOW_INSTANCE_NAME = os.environ["SNOW_INSTANCE_NAME"]
SNOW_SSPM_USERNAME = os.environ["SNOW_SSPM_USERNAME"]
SNOW_SSPM_PASSWORD = os.environ["SNOW_SSPM_PASSWORD"]
SNOW_FAILED_LOGIN_BREACHING_RATE = os.environ["SNOW_FAILED_LOGIN_BREACHING_RATE"]

def get_servicenow_sys_properties(cache: dict):
    """
    Pulls the entire Systems Properties table
    """
    response = cache.get("get_servicenow_sys_properties")
    if response:
        print("servicenow.access_control cache hit!")
        return response
    
    # Will need to create the pysnow.Client object everywhere - doesn't appear to be thread-safe
    snow = pysnow.Client(
        instance=SNOW_INSTANCE_NAME,
        user=SNOW_SSPM_USERNAME,
        password=SNOW_SSPM_PASSWORD
    )

    sysPropResource = snow.resource(api_path='/table/sys_properties')
    sysProps = sysPropResource.get().all()

    cache["get_servicenow_sys_properties"] = sysProps

    return cache["get_servicenow_sys_properties"]
```

In the above example, the Constants are provided into the `pysnow.Client()` object themselves, when developed multi-instance/multi-tenant/multi-account checks ensure that the environment-looping is down within `eeauditor.py` and not within the individual Auditors.

### Registering and Defining Checks

When Auditors and their Checks are registered by the `CheckRegister()` function, a [Decorator](https://realpython.com/primer-on-python-decorators/) is used to intake this information and it is important for both listing and executing checks, as well as determining when to reuse the Cache dictionary.

For consistency, always use the service name of whatever the specific Auditor is looking at, for multi-purpose or special-purpose Auditors you can name these registry Decorators as whatever the purpose is such as `@registry.register_check("shodan")` but always attempt to use a specific Service name. ElectricEye makes a best effort to strongly-order these Checks so if multiple Auditors use the same type of Cache it avoids extra API calls outbound from the function. In the case of SSPM checks, the usage of "dot-separation" within the registry title is used to disambiguated between products or Auditor-purpose such as `@registry.register_check("servicenow.attachments")` for ServiceNow Attachments security best practices and `@registry.register_check("servicenow.securityplugins")` for ServiceNow Plugin checks according to security best practices.

The arguments expected by check Auditor are defined in `eeauditor.py` and should follow the ordering defined there. For instance, AWS checks expect `(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str)` and GCP checks expect `(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str)`. For consistency, always declare the Python `type` in these arguments for Exception-handling within `eeauditor.py`. You can optionally output as a `-> dict:` at the end of the function arguments.

Lastly, within a double-quoted comment block, the Title of the specific Check should be defined. The naming convention is always `[{Service Name ***OR*** Special Purpose}.{Check Number}] {Check Title}` to keep consistency with the old style of AWS Security Hub having per-Check "control IDs" within the Title, this is kept for backwards compatability. In the case of SSPM Checks, their Title convention should be `[SSPM.{Service Name ***OR*** Special Purpose}.{Check Number}] {Check Title}`

Here is an example for an AWS registration with [`Amazon_EC2_Image_Builder_Auditor.py`](./eeauditor/auditors/aws/Amazon_EC2_Image_Builder_Auditor.py)

```python
@registry.register_check("imagebuilder")
def imagebuilder_pipeline_tests_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
"""[ImageBuilder.1] Image pipeline tests should be enabled"""
```

This is an example for a ServiceNow registration for [`Servicenow_Attachments_Auditor.py`](./eeauditor/auditors/servicenow/Servicenow_Attachments_Auditor.py)

@registry.register_check("servicenow.attachments")
def servicenow_sspm_downloadable_mime_types_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.Attachments.1] Instance should restrict the file types from being rendered in the browser to avoid any hidden malicious script execution
    """

This is an example for a Google Cloud Platform (GCP) Auditor for CloudSQL instances ([`GCP_CloudSQL_Auditor.py`](./eeauditor/auditors/gcp/GCP_CloudSQL_Auditor.py))

@registry.register_check("cloudsql")
def cloudsql_instance_public_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, gcpProjectId: str):
    """
    [GCP.CloudSQL.1] CloudSQL Instances should not be publicly reachable
    """

### Formatting Findings

Findings will be formatted for AWS Security Hub, [ASSF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html). Look to other auditors findings format for more specifics on ElectricEye formatting. Parts that will stay consistent across checks are: `SchemaVersion`, `ProductArn`, `AwsAccountId`, `FirstObservedAt`, `CreatedAt`, `UpdatedAt`, `ProductFields`, and the `Resources` array. Example finding formatting from `Amazon_EC2_Auditor` IMDSv2 Check:


```python
finding = {
    "SchemaVersion": "2018-10-08",
    "Id": instanceArn + "/ec2-imdsv2-check",
    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
    "GeneratorId": instanceArn,
    "AwsAccountId": awsAccountId,
    "Types": [
        "Software and Configuration Checks/AWS Security Best Practices",
        "Effects/Data Exposure"
    ],
    "FirstObservedAt": iso8601Time,
    "CreatedAt": iso8601Time,
    "UpdatedAt": iso8601Time,
    "Severity": {"Label": "MEDIUM"},
    "Confidence": 99,
    "Title": "[EC2.1] EC2 Instances should be configured to use instance metadata service V2 (IMDSv2)",
    "Description": "EC2 Instance "
    + instanceId
    + " is not configured to use instance metadata service V2 (IMDSv2). IMDSv2 adds new “belt and suspenders” protections for four types of vulnerabilities that could be used to try to access the IMDS. These new protections go well beyond other types of mitigations, while working seamlessly with existing mitigations such as restricting IAM roles and using local firewall rules to restrict access to the IMDS. Refer to the remediation instructions if this configuration is not intended",
    "Remediation": {
        "Recommendation": {
            "Text": "To learn how to configure IMDSv2 refer to the Transitioning to Using Instance Metadata Service Version 2 section of the Amazon EC2 User Guide",
            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html#instance-metadata-transition-to-version-2",
        }
    },
    "ProductFields": {"ProductName": "ElectricEye"},
    "Resources": [
        {
            "Type": "AwsEc2Instance",
            "Id": instanceArn,
            "Partition": awsPartition,
            "Region": awsRegion,
            "Details": {
                "AwsEc2Instance": {
                    "Type": instanceType,
                    "ImageId": instanceImage,
                    "VpcId": vpcId,
                    "SubnetId": subnetId,
                    "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                }
            },
        }
    ],
    "Compliance": {
        "Status": "FAILED",
        "RelatedRequirements": [
            "NIST CSF PR.AC-4",
            "NIST SP 800-53 AC-1",
            "NIST SP 800-53 AC-2",
            "NIST SP 800-53 AC-3",
            "NIST SP 800-53 AC-5",
            "NIST SP 800-53 AC-6",
            "NIST SP 800-53 AC-14",
            "NIST SP 800-53 AC-16",
            "NIST SP 800-53 AC-24",
            "AICPA TSC CC6.3",
            "ISO 27001:2013 A.6.1.2",
            "ISO 27001:2013 A.9.1.2",
            "ISO 27001:2013 A.9.2.3",
            "ISO 27001:2013 A.9.4.1",
            "ISO 27001:2013 A.9.4.4",
            "ISO 27001:2013 A.9.4.5"
        ]
    },
    "Workflow": {"Status": "NEW"},
    "RecordState": "ACTIVE"
}
yield finding
```

While not required by ASFF, it is required by ElectricEye that all checks are mapped to the supported compliance standards. It is recommended to use the mapped `Compliance.Requirements` from an existing Check within an Auditor that is similar to yours - for instance - if you are developing a check around TLS, look for an example of a Check for encryption in transit. If you are developing a check to enable Logging, look for a Check that deals with Logging.

For AWS, The `Resources.Id` should **ALWAYS** be an ARN, not every Boto3 Client nor Function within will return an ARN and you may need to look up what the ARN looks like, refer to the **[Actions, resources, and condition keys for AWS services](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html)** section of the Service Authorization Reference. For other services, use whatever the CSP or SaaS Provider provides as a GUID, canonical ID, or other unique record or value locator / identifier.

In the case of GCP, a GUID is constructed from the GCP Project ID, Zone and Name as shown below, e.g., `"Id": f"{gcpProjectId}/{zone}/{name}"`

```python
{...}
"Resources": [
    {
        "Type": "GcpCloudSqlInstance",
        "Id": f"{gcpProjectId}/{zone}/{name}",
        "Partition": awsPartition,
        "Region": awsRegion,
        "Details": {
            "Other": {
                "GcpProjectId": gcpProjectId,
                "Zone": zone,
                "Name": name,
                "DatabaseVersion": databaseVersion,
                "MaintenanceVersion": maintenanceVersion,
                "CreatedAt": createTime,
                "State": state,
                "IpAddress": ipAddress,
            }
        }
    }
],
{...}
```

In the case of ServiceNow, a GUID is constructed from the ServiceNow Instance Name, the table name the Auditor is written against, and the specific `sys_id` within the ServiceNow table, e.g., `f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}"`

```python
{...}
"Resources": [
    {
        "Type": "ServicenowInstance",
        "Id": f"{SNOW_INSTANCE_NAME}/sys_properties/{evalTarget}",
        "Partition": awsPartition,
        "Region": awsRegion,
        "Details": {
            "Other": {
                "ServicenowInstance": SNOW_INSTANCE_NAME,
                "SysId": propId,
                "PropertyName": evalTarget,
                "PropertyValue": propertyValue,
                "Description": propDescription,
                "CreatedBy": propCreatedBy,
                "CreatedOn": propCreatedOn,
                "UpdatedBy": propUpdatedBy,
                "UpdatedOn": propUpdatedOn,
                "Scope": propScope
            }
        }
    }
],
{...}
```

For the `Resource.Type` within ASFF, this should map to the top level Resource type, im AWS this is relatively easy as the ASFF maps out several dozen of these such as `AwsApiGatewayStage` or `AwsEc2Instance`. The key value is a String and ***IS NOT ENUM-BACKED*** so it can be nearly anything you want. This is used for searching and filtering with AWS Security Hub and other outputs so it should be consistent with *what* is being evaluated.

For instance, in the above ServiceNow `Resources[*]` example, `"Type": "ServicenowInstance"` is used as the `sys_property` table within ServiceNow is aligned to the specific Instance and are in turn *properties of the specific instance* so that is why `ServicenowInstance` is used. 

For the `.Description`, `Remediation.Recommendation.Text` and `Remediation.Recommendation.Url` when possible, **ALWAYS** use the official provider documentation URLs and reccomendations for those sections of the ASFF. You should include a short description and note what Section and which Guide you are using. This additional meta-descriptiveness sould also be applied to the `Description` of a *failing* finding, as demonstrated below.

```python
"Title": "[SSPM.Servicenow.Attachments.1] Instance should restrict the file types from being rendered in the browser to avoid any hidden malicious script execution",
"Description": f"Servicenow instance {SNOW_INSTANCE_NAME} does not restrict the file types from being rendered in the browser to avoid any hidden malicious script execution. Use the 'glide.ui.attachment.download_mime_types' property to specify a list of comma-separated attachment MIME types that should be downloaded but not render inline in the browser. Client-side scripting attack vectors come in different flavors and MIME type attachment abuse is no exception. Attackers can abuse MIME types and place unintended script content in the attachment on the victim's side to capture sensitive information. In the current context, populate the property with a list of comma-separated attachment mime types that should not render inline in the browser.  Refer to the remediation instructions if this configuration is not intended.",
"Remediation": {
    "Recommendation": {
        "Text": "For more information refer to the Downloadable MIME types (instance security hardening) section of the Servicenow Product Documentation.",
        "Url": "https://docs.servicenow.com/bundle/utah-platform-security/page/administer/security/reference/download-mime-types.html",
    }
},
```

Lastly, ElectricEye has an asset-reporting capability that should be defined within `.ProductFields` such as the below example. Refer to the [Cloud Asset Management docs](../asset_management/ASSET_MANAGEMENT.md) for information on this schema and its design principles.

```python
"ProductFields": {
    "ProductName": "ElectricEye",
    "Provider": "AWS",
    "ProviderType": "CSP",
    "ProviderAccountId": awsAccountId,
    "AssetRegion": awsRegion,
    "AssetDetails": assetB64,
    "AssetClass": "Networking",
    "AssetService": "Amazon API Gateway",
    "AssetComponent": "Stage"
}
```

The Asset Details in the `assetB64` variable are a Base64 encoded JSON object about the `AssetComponent` itself, in cases where a Check is written about an Account or a series of configurations, the `AssetDetails` should be aligned against the high level check or hard-code as `None`. The example below shows the loop for capturing `assetB64` for an Amazon API Gateway Stage.

```python
for restapi in get_rest_apis(cache, session)["items"]:
    apiGwApiId = str(restapi["id"])
    apiGwApiName = str(restapi["name"])
    response = apigateway.get_stages(restApiId=apiGwApiId)
    for apistages in response["item"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(apistages,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
```

### Creating Tests

For each check within an auditor there should be a corresponding test for each case the check could come across, often times a pass and fail but sometimes more. A stubber is used to give the auditor the desired responses for testing. Necessary imports are:

```python
import datetime
import os
import pytest
import sys

from botocore.stub import Stubber, ANY
```

### Auditor testing

TODO: EXPAND THIS SHIT...

1. Install dependencies

```bash
pip3 install -r requirements-dev.txt
```

2. Run pytest

```bash
pytest
```

Existing, (and limited!) tests are located in the [EEAuditor Tests folder](../../eeauditor/tests/) and individual test can be run by adding the path with the name of the file after `pytest`.