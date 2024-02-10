import requests
import json

data = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json").text

data = json.loads(data)

controls = []

for item in data["objects"]:
    try:
        for ref in item["external_references"]:
            if "external_id" in ref:
                extId = str(ref["external_id"])
                if not extId.startswith("T"):
                    continue
                controlId = f"MITRE ATT&CK {extId}"
                description = item["name"] + " : " + item["description"]

                controls.append(
                    {
                        "ControlTitle": controlId,
                        "ControlDescription": description
                    }
                )
            else:
                continue
    except KeyError:
        continue

with open("./new.json", "w") as jsonfile:
    json.dump(
        controls,
        jsonfile,
        indent=2,
        default=str
    )