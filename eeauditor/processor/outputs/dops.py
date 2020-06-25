import json
import os
import requests
from processor.outputs.output_base import ElectricEyeOutput

url = os.environ.get("DOPS_COLLECTOR_URL")
client_id = os.environ.get("DOPS_CLIENT_ID")
api_key = os.environ.get("DOPS_API_KEY")


@ElectricEyeOutput
class DopsProvider(object):
    __provider__ = "dops"

    def __init__(self):


    def write_findings(self, findings: list, **kwargs):
        if client_id and api_key and url:
            for finding in findings:
                response = requests.post(
                    url, data=json.dumps(finding), auth=(client_id, api_key)
                )
        else:
            raise ValueError("Missing credentials for client_id or api_key")
