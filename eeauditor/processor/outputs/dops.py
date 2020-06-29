import boto3
import json
import os
import requests
from processor.outputs.output_base import ElectricEyeOutput

ssm = boto3.client("ssm")

dops_client_id_param = os.environ["DOPS_CLIENT_ID_PARAM"]
dops_api_key_param = os.environ["DOPS_API_KEY_PARAM"]

client_id_response = ssm.get_parameter(Name=dops_client_id_param, WithDecryption=True)
api_key_response = ssm.get_parameter(Name=dops_api_key_param, WithDecryption=True)

url = "https://collector.prod.disruptops.com/event"
client_id = str(client_id_response["Parameter"]["Value"])
api_key = str(api_key_response["Parameter"]["Value"])


@ElectricEyeOutput
class DopsProvider(object):
    __provider__ = "dops"

    def write_findings(self, findings: list, **kwargs):
        if client_id and api_key and url:
            for finding in findings:
                response = requests.post(
                    url, data=json.dumps(finding), auth=(client_id, api_key)
                )
        else:
            raise ValueError("Missing credentials for client_id or api_key")
