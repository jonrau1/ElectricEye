import boto3
import json
import os
import requests
from processor.outputs.output_base import ElectricEyeOutput


@ElectricEyeOutput
class DopsProvider(object):
    __provider__ = "dops"

    def __init__(self):
        ssm = boto3.client("ssm")

        dops_client_id_param = os.environ["DOPS_CLIENT_ID_PARAM"]
        dops_api_key_param = os.environ["DOPS_API_KEY_PARAM"]

        client_id_response = ssm.get_parameter(Name=dops_client_id_param, WithDecryption=True)
        api_key_response = ssm.get_parameter(Name=dops_api_key_param, WithDecryption=True)

        self.url = "https://collector.prod.disruptops.com/event"
        self.client_id = str(client_id_response["Parameter"]["Value"])
        self.api_key = str(api_key_response["Parameter"]["Value"])

    def write_findings(self, findings: list, **kwargs):
        print(f"Writing {len(findings)} results to DisruptOps")
        if self.client_id and self.api_key and self.url:
            for finding in findings:
                response = requests.post(
                    self.url, data=json.dumps(finding), auth=(self.client_id, self.api_key)
                )
        else:
            raise ValueError("Missing credentials for client_id or api_key")
