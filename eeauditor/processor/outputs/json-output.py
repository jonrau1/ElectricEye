import json
import os

from processor.outputs.output_base import ElectricEyeOutput


@ElectricEyeOutput
class JsonProvider(object):
    __provider__ = "json"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        first = True
        jsonfile = output_file + ".json"
        json_out_location = ""
        with open(jsonfile, "w") as json_out:
            print(f"Writing findings to {jsonfile}")
            print('{"Findings":[', file=json_out)
            json_out_location = os.path.abspath(json_out.name)
            for finding in findings:
                # print a comma separation between findings except before first finding
                if first:
                    first = False
                else:
                    print(",", file=json_out)
                json.dump(finding, json_out, indent=2)
            print("]}", file=json_out)
        json_out.close()
        return True
