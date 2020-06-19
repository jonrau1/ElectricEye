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


def main(argv):
    profile_name = ""
    auditor_name = ""
    check_name = ""
    output = False
    sechub = True
    output_file = ""
    print_checks = False
    delay = 0
    help_text = (
        "auditor.py [-p <profile_name> -a <auditor_name> -c <check_name> -o <output_file_name>]"
    )
    try:
        opts, args = getopt.getopt(
            argv,
            "ho:p:a:c:s:d:",
            [
                "help",
                "output=",
                "profile=",
                "auditor=",
                "check=",
                "sechub=",
                "printchecks",
                "delay=",
            ],
        )
    except getopt.GetoptError:
        print(help_text)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(help_text)
            sys.exit(2)
        if opt == "--printchecks":
            print_checks = True
        if opt in ("-o", "--output"):
            output = True
            output_file = arg
        if opt in ("-p", "--profile"):
            profile_name = arg.strip()
        if opt in ("-a", "--auditor"):
            auditor_name = arg.strip()
        if opt in ("-c", "--check"):
            check_name = arg
        if opt in ("-d", "--delay"):
            delay = float(arg)
        if opt in ("-s", "--sechub"):
            sechub = arg.lower() not in ["false", "False"]
    if profile_name:
        boto3.setup_default_session(profile_name=profile_name)

    app = EEAuditor(name="AWS Auditor")
    app.load_plugins(plugin_name=auditor_name)
    if print_checks == True:
        app.print_checks_md()
        sys.exit(2)
    json_out = app.run(sechub=sechub, output=output, check_name=check_name, delay=delay)
    print(f"Done.  Raw results {json_out}")


if __name__ == "__main__":
    # this is for local testing where the AWS_REGION is not liekly set
    # if not os.environ.get("AWS_REGION", None):
    # os.environ["AWS_REGION"] = "us-east-1"
    main(sys.argv[1:])
