# ElectricEye Outputs

This documentation is all about Outputs supported by ElectricEye and how to configure them with the Command-line and/or TOML file.

## Table of Contents

- [Key Considerations](#key-considerations)
- [JSON Output](#json-output)
- [Normalized JSON Output](#json-normalized-output)
- [Cloud Asset Management JSON Output](#json-cloud-asset-management-cam-output)
- [CSV Output](#csv-output)
- [AWS Security Hub Output](#aws-security-hub-output)
- [MongoDB & AWS DocumentDB Output](#mongodb--aws-documentdb-output)
- [Cloud Asset Management MongoDB & AWS DocumentDB Output](#mongodb--aws-documentdb-cloud-asset-management-cam-output)
- [PostgreSQL Output](#postgresql-output)
- [Cloud Asset Management PostgreSQL Output](#postgresql-cloud-asset-management-cam-output)
- [Firemon Cloud Defense (DisruptOps) Output](#firemon-cloud-defense-disruptops-output)
- [`stdout` Output](#stdout-output)

## Key Considerations

ElectricEye supports several cloud-native, open-source, and file-based Outputs and can process one or more different Output providers to support multi-reporting use cases. Best effort is made to implement best-practices per-provider such as setting Primary Keys in MongoDB and PostgreSQL, using Upserts, exponetial backoffs, batch writing, and/or graceful exception handling when possible.

As these outputs contain sensitive values such as API Keys, Tenant IDs, Passwords, and similar credentials it is always a best practice to use AWS Systems Manager Parameter Store SecureString Parameters or AWS Secrets Manager. In the future, other password vaults and Privileged Identity Management (PIM) solutions will be supported.

To review the list of possible Output providers, use the following ElectricEye command.

    ```bash
    $ python3 eeauditor/controller.py --list-options
    ['firemon_cloud_defense', 'json', 'sechub', 'json_normalized', 'postgresql', 'cam_json', 'csv', 'stdout', 'mongodb', 'ddb_backend', 'cam_postgresql']
    ```

For ***file-based Ouputs*** such as JSON or CSV, the filename is controlled using the `--output-file` argument, if provided for other Outputs it will be ignored. Note that you do not need to specify a MIME type (e.g., `.csv`, `.json`), this will be handled by the Output Processor

    ```bash
    $ python3 eeauditor/controller.py --output-file my_important_file -o json -t AWS -a Amazon_EC2_Auditor
    ```

All other Output attributes are controlled in the [TOML Configuration File](../../eeauditor/external_providers.toml) underneath the `[Outputs]` heading, ensure that any sensitive values you provide match the selection within `[global.credentials_location]`. At this time, it is **NOT POSSIBLE** to mix-and-match credential locations between local files, SSM, ASM, or otherwise.

    ```toml
    # This TOML document provides configuration for all of ElectricEye, from credentials to regions to accounts 
    # as well as global settings, filenames, and other directives that can be used by ElectricEye

    title = "ElectricEye Configuration"

    [global]

        # Match this to [regions_and_accounts.aws.aws_account_targets] to specify if you want to run ElectricEye
        # against a list of Accounts, list of Accounts within specific OUs, or every Account in an AWS Organization

        aws_multi_account_target_type = "Accounts" # VALID CHOICES: Accounts | OU | Organization

        # Specifies the location of where credentials are stored and will be retrieved from
        # if you specify "CONFIG_FILE" that means you can provide the value within the option itself

        credentials_location = "AWS_SSM" # VALID CHOICES: AWS_SSM | AWS_SECRETS_MANAGER | CONFIG_FILE
    ```

Each Output Processor will raise an `Exception` if there are missing or conflicting values, ensure you review the instructions within this documentation or within the TOML file commentary. For a better user experience, it is recommended to view the TOML file within an Integrated Development Environment (IDE) such as VSCode with a .TOML parsing extension.

## JSON Output

Remarks

## JSON "Normalized" Output

Remarks

## JSON Cloud Asset Management (CAM) Output

Remarks

## CSV Output

Remarks

## AWS Security Hub Output

Remarks

## MongoDB & AWS DocumentDB Output

Remarks

## MongoDB & AWS DocumentDB Cloud Asset Management (CAM) Output

Remarks

## PostgreSQL Output

Remarks

## PostgreSQL Cloud Asset Management (CAM) Output

Remarks

## Firemon Cloud Defense (DisruptOps) Output

Remarks

## `stdout` Output

Remarks