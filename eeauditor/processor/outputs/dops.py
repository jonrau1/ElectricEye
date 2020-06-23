import json
import os
import requests
from processor.outputs.output_base import ElectricEyeOutput


@ElectricEyeOutput
class DopsProvider(object):
    __provider__ = "dops"

    def __init__(self):
        self.url = os.environ.get("DOPS_COLLECTOR_URL")
        self.client_id = os.environ.get("DOPS_CLIENT_ID")
        self.api_key = os.environ.get("DOPS_API_KEY")

    def write_findings(self, findings: list, **kwargs):
        if self.client_id and self.api_key:
            for finding in findings:
                response = requests.post(
                    self.url, data=json.dumps(finding), auth=(self.client_id, self.api_key)
                )
        else:
            raise ValueError("Missing credentials for client_id or api_key")
