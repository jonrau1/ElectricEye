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
import json

from . import context
from eeauditor import EEAuditor
from .test_modules.plugin1 import plugin_func_1


def test_eeauditor_plugin_loader():
    app = EEAuditor(name="test controller", search_path="./tests/test_modules")
    app.load_plugins()
    for k, v in app.registry.checks["test"].items():
        assert k == "plugin_func_1"


def test_eeauditor_plugin_loader_named():
    app = EEAuditor(name="test controller", search_path="./tests/test_modules")
    app.load_plugins(plugin_name="plugin1")
    for k, v in app.registry.checks["test"].items():
        assert k == "plugin_func_1"


def test_eeauditor_plugin_run_checks():
    app = EEAuditor(name="test controller", search_path="./tests/test_modules")
    # Since other tests are importing auditor modules that register checks in the
    # registry, it is possible checks other than those in the search_path will be
    # loaded and run here.  This statement clears the checks dictionary prior to
    # calling load_plugins
    app.registry.checks.clear()
    app.load_plugins()
    for result in app.run_checks():
        assert result == {"SchemaVersion": "2018-10-08", "Id": "test-finding"}


def test_eeauditor_plugin_run_one_check():
    app = EEAuditor(name="test controller", search_path="./tests/test_modules")
    app.load_plugins(plugin_name="plugin1")
    for result in app.run_checks(requested_check_name="plugin_func_1"):
        assert result == {"SchemaVersion": "2018-10-08", "Id": "test-finding"}
