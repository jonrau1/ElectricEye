from processor.outputs.output_base import SecurityBotOutput


def process_findings(findings: list, outputs: list, **kwargs):
    """Process all findings from json file and send to outputs sepecified"""
    for output in outputs:
        try:

            SecurityBotOutput.get_provider(output)().write_findings(findings=findings, **kwargs)
        except Exception as e:
            print(f"Error writing output: {e}")


def get_providers():
    return SecurityBotOutput.get_all_providers()
