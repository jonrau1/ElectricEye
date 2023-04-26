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

registry = CheckRegister()

@registry.register_check("imagebuilder")
def imagebuilder_pipeline_tests_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ImageBuilder.1] Image pipeline tests should be enabled"""
    imagebuilder = session.client("imagebuilder")
    pipelines = imagebuilder.list_image_pipelines()
    pipeline_list = pipelines["imagePipelineList"]
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for arn in pipeline_list:
        pipelineArn = arn["arn"]
        pipeline_name = arn["name"]
        image_pipelines = imagebuilder.get_image_pipeline(imagePipelineArn=pipelineArn)
        image_test_config = image_pipelines["imagePipeline"]["imageTestsConfiguration"]
        image_test_enabled = image_test_config["imageTestsEnabled"]
        if image_test_enabled == True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": pipelineArn + "/imagebuilder-pipeline-tests-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": pipelineArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ImageBuilder.1] Image pipeline tests should be enabled",
                "Description": "Image pipeline " + pipeline_name + " has tests enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on EC2 Image Builder Security and enabling image testing refer to the Best Practices section of the Amazon EC2 Image Builder Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/imagebuilder/latest/userguide/security-best-practices.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS EC2 Image Builder",
                    "AssetType": "Pipeline"
                },
                "Resources": [
                    {
                        "Type": "AwsImageBuilderPipeline",
                        "Id": pipelineArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": 
                            {
                                "PipelineName": pipeline_name
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
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": pipelineArn + "/imagebuilder-pipeline-tests-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": pipelineArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ImageBuilder.1] Image pipeline tests should be enabled",
                "Description": "Image pipeline " + pipeline_name + " does not have tests enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on EC2 Image Builder Security and enabling image testing refer to the Best Practices section of the Amazon EC2 Image Builder Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/imagebuilder/latest/userguide/security-best-practices.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS EC2 Image Builder",
                    "AssetType": "Pipeline"
                },
                "Resources": [
                    {
                        "Type": "AwsImageBuilderPipeline",
                        "Id": pipelineArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": 
                            {
                                "PipelineName": pipeline_name
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
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("imagebuilder")
def imagebuilder_ebs_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ImageBuilder.2] Image recipes should encrypt EBS volumes"""
    imagebuilder = session.client("imagebuilder")
    recipes = imagebuilder.list_image_recipes()
    recipes_list = recipes["imageRecipeSummaryList"]
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for details in recipes_list:
        recipeArn = details["arn"]
        recipe_name = details["name"]
        recipe = imagebuilder.get_image_recipe(imageRecipeArn=recipeArn)
        device_mapping = recipe["imageRecipe"]["blockDeviceMappings"]
        list1 = device_mapping[0]
        ebs = list1["ebs"]
        ebs_encryption = ebs["encrypted"]
        if ebs_encryption == True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": recipeArn + "/imagebuilder-ebs-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": recipeArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ImageBuilder.2] Image recipes should encrypt EBS volumes",
                "Description": "Image recipe " + recipe_name + " has EBS encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on EC2 Image Builder Security and EBS encyption refer to the How EC2 Image Builder Works section of the Amazon EC2 Image Builder Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/imagebuilder/latest/userguide/how-image-builder-works.html#image-builder-components",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS EC2 Image Builder",
                    "AssetType": "Recipe"
                },
                "Resources": [
                    {
                        "Type": "AwsImageBuilderRecipe",
                        "Id": recipeArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": 
                            {
                                "RecipeName": recipe_name
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
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": recipeArn + "/imagebuilder-ebs-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": recipeArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ImageBuilder.2] Image recipes should encrypt EBS volumes",
                "Description": "Image recipe " + recipe_name + " does not have EBS encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on EC2 Image Builder Security and EBS encyption refer to the How EC2 Image Builder Works section of the Amazon EC2 Image Builder Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/imagebuilder/latest/userguide/how-image-builder-works.html#image-builder-components",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS EC2 Image Builder",
                    "AssetType": "Recipe"
                },
                "Resources": [
                    {
                        "Type": "AwsImageBuilderRecipe",
                        "Id": recipeArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": 
                            {
                                "RecipeName": recipe_name
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
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding