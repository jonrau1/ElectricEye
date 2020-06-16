import json
import os

from . import context
from eeauditor import EEAuditor
from .test_modules.plugin1 import plugin_func_1

os.environ["AWS_REGION"] = "us-east-1"


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
    app.load_plugins()
    for result in app.run_checks():
        assert result == {"SchemaVersion": "2018-10-08", "Id": "test-finding"}


def test_eeauditor_plugin_run_one_check():
    app = EEAuditor(name="test controller", search_path="./tests/test_modules")
    app.load_plugins(plugin_name="plugin1")
    for result in app.run_checks(requested_check_name="plugin_func_1"):
        assert result == {"SchemaVersion": "2018-10-08", "Id": "test-finding"}


def test_eeauditor_run():
    app = EEAuditor(name="test controller", search_path="./tests/test_modules")
    app.load_plugins(plugin_name="plugin1")
    output_file = app.run(sechub=False, output=False, check_name="plugin_func_1")
    with open(output_file) as f:
        findings_file = json.load(f)
        findings = findings_file["Findings"]
        assert findings == [{"SchemaVersion": "2018-10-08", "Id": "test-finding"}]
    f.close()
