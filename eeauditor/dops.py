import json
import requests

url = "https://collector.dev2.disruptops.com/event"
client_id = "9c1de1ee-7d73-4d06-8010-92148ac9f236"
api_key = "41ad9cf162013f4a7e7614dff7b5738cf12d233c7821a29d"


def send_findings(findings: list):
    for finding in findings:
        try:
            requests.post(url, data=json.dumps(finding), auth=(client_id, api_key))
        except Exception as e:
            print(e)
