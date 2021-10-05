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
from auditors.aws.Amazon_EC2_Image_Builder_Auditor import (
    imagebuilder_pipeline_tests_enabled_check,
    imagebuilder_ebs_encryption_check,
    imagebuilder,
)

list_image_pipelines_response = {
    'requestId': 'string',
    'imagePipelineList': [
        {
            'arn': 'arn:aws:imagebuilder:us-east-2:123456789012:image-pipeline/testpipeline',
            'name': 'testpipeline',
            'description': 'string',
            'platform': 'Windows',
            'enhancedImageMetadataEnabled': True|False,
            'imageRecipeArn': 'string',
            'infrastructureConfigurationArn': 'string',
            'distributionConfigurationArn': 'string',
            'imageTestsConfiguration': {
                'imageTestsEnabled': True|False,
                'timeoutMinutes': 123
            }
        }
    ]
}

get_image_pipeline_response1 = {
    "requestId": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
    "imagePipeline": {
        "arn": 'arn:aws:imagebuilder:us-east-2:123456789012:image-pipeline/testpipeline',
        "name": "testpipeline",
        "description": "Builds Windows 2016 Images",
        "platform": "Windows",
        "imageRecipeArn": "arn:aws:imagebuilder:us-west-2:123456789012:image-recipe/mybasicrecipe/2019.12.03",
        "infrastructureConfigurationArn": "arn:aws:imagebuilder:us-west-2:123456789012:infrastructure-configuration/myexampleinfrastructure",
        "distributionConfigurationArn": "arn:aws:imagebuilder:us-west-2:123456789012:distribution-configuration/myexampledistribution",
        "imageTestsConfiguration": {
            "imageTestsEnabled": True,
            "timeoutMinutes": 60
        }
    }
}

get_image_pipeline_response2 = {
    "requestId": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
    "imagePipeline": {
        "arn": 'arn:aws:imagebuilder:us-east-2:123456789012:image-pipeline/testpipeline',
        "name": "testpipeline",
        "description": "Builds Windows 2016 Images",
        "platform": "Windows",
        "imageRecipeArn": "arn:aws:imagebuilder:us-west-2:123456789012:image-recipe/mybasicrecipe/2019.12.03",
        "infrastructureConfigurationArn": "arn:aws:imagebuilder:us-west-2:123456789012:infrastructure-configuration/myexampleinfrastructure",
        "distributionConfigurationArn": "arn:aws:imagebuilder:us-west-2:123456789012:distribution-configuration/myexampledistribution",
        "imageTestsConfiguration": {
            "imageTestsEnabled": False,
            "timeoutMinutes": 60
        }
    }
}

list_image_recipes_response = {
    'requestId': 'string',
    'imageRecipeSummaryList': [
        {
            'arn':'arn:aws:imagebuilder:us-east-2:123456789012:image-pipeline/testpipeline',
            'name': 'testpipeline',
            'platform': 'Linux',
            'owner': 'string',
            'parentImage': 'string',
            'dateCreated': 'string',
            'tags': {
                'string': 'string'
            }
        }
    ]
}

get_image_recipe_response1 = {
    'requestId': 'string',
    'imageRecipe': {
        'arn':'arn:aws:imagebuilder:us-east-2:123456789012:image-pipeline/testpipeline',
        'name': 'testpipeline',
        'description': 'string',
        'platform': 'Linux',
        'owner': 'string',
        'version': 'string',
        'components': [
            {
                'componentArn': 'string'
            },
        ],
        'parentImage': 'string',
        'blockDeviceMappings': [
            {
                'deviceName': 'string',
                'ebs': {
                    'encrypted': True,
                    'deleteOnTermination': True|False,
                    'iops': 123,
                    'kmsKeyId': 'string',
                    'snapshotId': 'string',
                    'volumeSize': 123,
                    'volumeType': 'standard'
                }
            }
        ]
    }
}

get_image_recipe_response2 = {
    'requestId': 'string',
    'imageRecipe': {
        'arn':'arn:aws:imagebuilder:us-east-2:123456789012:image-pipeline/testpipeline',
        'name': 'testpipeline',
        'description': 'string',
        'platform': 'Linux',
        'owner': 'string',
        'version': 'string',
        'components': [
            {
                'componentArn': 'string'
            },
        ],
        'parentImage': 'string',
        'blockDeviceMappings': [
            {
                'deviceName': 'string',
                'ebs': {
                    'encrypted': False,
                    'deleteOnTermination': True|False,
                    'iops': 123,
                    'kmsKeyId': 'string',
                    'snapshotId': 'string',
                    'volumeSize': 123,
                    'volumeType': 'standard'
                }
            }
        ]
    }
}

@pytest.fixture(scope="function")
def imagebuilder_stubber():
    imagebuilder_stubber = Stubber(imagebuilder)
    imagebuilder_stubber.activate()
    yield imagebuilder_stubber
    imagebuilder_stubber.deactivate()

def test_is_enabled(imagebuilder_stubber):
    imagebuilder_stubber.add_response("list_image_pipelines", list_image_pipelines_response)
    imagebuilder_stubber.add_response("get_image_pipeline", get_image_pipeline_response1)
    results = imagebuilder_pipeline_tests_enabled_check(
        cache={}, awsAccountId="0123456789012", awsRegion="us-east-2", awsPartition="aws"
    )
    for result in results:
        if "testpipeline" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    imagebuilder_stubber.assert_no_pending_responses()

def test_not_enabled(imagebuilder_stubber):
    imagebuilder_stubber.add_response("list_image_pipelines", list_image_pipelines_response)
    imagebuilder_stubber.add_response("get_image_pipeline", get_image_pipeline_response2)
    results = imagebuilder_pipeline_tests_enabled_check(
        cache={}, awsAccountId="0123456789012", awsRegion="us-east-2", awsPartition="aws"
    )
    for result in results:
        if "testpipeline" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    imagebuilder_stubber.assert_no_pending_responses()

def test_ebs_is_encrypted(imagebuilder_stubber):
    imagebuilder_stubber.add_response("list_image_recipes", list_image_recipes_response)
    imagebuilder_stubber.add_response("get_image_recipe", get_image_recipe_response1)
    results = imagebuilder_ebs_encryption_check(
        cache={}, awsAccountId="0123456789012", awsRegion="us-east-2", awsPartition="aws"
    )
    for result in results:
        if "testpipeline" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ARCHIVED"
        else:
            assert False
    imagebuilder_stubber.assert_no_pending_responses()

def test_ebs_not_encrypted(imagebuilder_stubber):
    imagebuilder_stubber.add_response("list_image_recipes", list_image_recipes_response)
    imagebuilder_stubber.add_response("get_image_recipe", get_image_recipe_response2)
    results = imagebuilder_ebs_encryption_check(
        cache={}, awsAccountId="0123456789012", awsRegion="us-east-2", awsPartition="aws"
    )
    for result in results:
        if "testpipeline" in result["Id"]:
            print(result["Id"])
            assert result["RecordState"] == "ACTIVE"
        else:
            assert False
    imagebuilder_stubber.assert_no_pending_responses()