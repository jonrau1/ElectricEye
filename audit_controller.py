import json
import boto3
from auditors.Auditor import Auditor, AuditorCollection


def main():
    boto3.setup_default_session(profile_name="hooli")
    auditors = AuditorCollection("auditors")
    securityhub = boto3.client("securityhub")
    for plugin in auditors.plugins:
        findings = []
        try:
            print(f"Executing auditor: {plugin.name}")
            for finding in plugin.execute():
                findings.append(finding)
                if finding["RecordState"] == "ACTIVE":
                    print(json.dumps(finding, indent=2))
            if findings:
                response = securityhub.batch_import_findings(Findings=findings)
        except:
            print(f"Error running plugin {plugin.name}")


if __name__ == "__main__":
    main()
