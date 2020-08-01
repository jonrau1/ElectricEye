from processor.outputs.output_base import ElectricEyeOutput


def process_findings(findings: list, outputs: list, **kwargs):
    """Process all findings from json file and send to outputs specified"""
    print(f"main.py -> process_findings method START")
    for output in outputs:
        try:

            ElectricEyeOutput.get_provider(output)().write_findings(findings=findings, **kwargs)
        except Exception as e:
            print(f"Error writing output: {e}")
    print(f"main.py -> process_findings method END")


def get_providers():
    return ElectricEyeOutput.get_all_providers()
