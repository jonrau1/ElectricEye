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

import logging
from sys import exit as sysexit

logger = logging.getLogger("OutputBase")

class ElectricEyeOutput(object):
    """Class to be used as a decorator to register all output providers"""

    _outputs = {}

    def __new__(cls, output):
        ElectricEyeOutput._outputs[output.__provider__] = output
        return output

    @classmethod
    def get_provider(cls, provider):
        """Returns the class to process the findings"""
        try:
            return cls._outputs[provider]
        except KeyError as ke:
            logger.warning(
                "Designated output provider %s does not exist", provider
            )
            sysexit(2)

    @classmethod
    def get_all_providers(cls):
        """Return a list of all the possible output providers"""
        return [*cls._outputs]