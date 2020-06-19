# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

import getopt
import os
import sys

import boto3

from eeauditor import EEAuditor
from processor.main import get_providers, process_findings


def print_checks():
    app = EEAuditor(name="AWS Auditor")
    app.load_plugins()
    app.print_checks_md()


def run_auditor(auditor_name=None, check_name=None, delay=0, outputs=None, output_file=""):
    if not outputs:
        outputs = ["sechub"]
    app = EEAuditor(name="AWS Auditor")
    app.load_plugins(plugin_name=auditor_name)
    findings = list(app.run_checks(requested_check_name=check_name, delay=delay))
    result = process_findings(findings=findings, outputs=outputs, output_file=output_file)
    print(f"Done.")


def main(argv):
    profile_name = ""
    auditor_name = ""
    check_name = ""
    outputs = []
    output_file = "output"
    delay = 0
    help_text = "auditor.py [--profile <profile_name> --auditor <auditor_name> -check <check_name> --delay <delay_time> --outputs <output format list> --output-file <output_file_name> --list-outputs --print-checks ]"
    try:
        opts, args = getopt.getopt(
            argv,
            "ho:p:a:c:d:",
            [
                "help",
                "outputs=",
                "output-file=",
                "profile=",
                "auditor=",
                "check=",
                "print-checks",
                "delay=",
                "list-outputs",
            ],
        )
    except getopt.GetoptError:
        print(help_text)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(help_text)
            sys.exit(2)
        if opt == "--list-outputs":
            print(get_providers())
            sys.exit(2)
        if opt == "--print-checks":
            print_checks()
            sys.exit(2)
        if opt in ("-o", "--outputs"):
            outputs.append(arg)
        if opt in ("-p", "--profile"):
            profile_name = arg.strip()
        if opt in ("-a", "--auditor"):
            auditor_name = arg.strip()
        if opt in ("-c", "--check"):
            check_name = arg
        if opt in ("-d", "--delay"):
            delay = float(arg)

    if profile_name:
        boto3.setup_default_session(profile_name=profile_name)

    run_auditor(
        auditor_name=auditor_name,
        check_name=check_name,
        delay=delay,
        outputs=outputs,
        output_file=output_file,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
