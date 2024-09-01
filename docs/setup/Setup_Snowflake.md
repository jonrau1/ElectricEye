# ElectricEye SaaS Security Posture Management (SSPM) for Snowflake

This documentation is dedicated to using ElectricEye for evaluation of Snowflake enterprise data warehouses using SSPM capabilities.

## Table of Contents

## Setting up Snowflake Permissions

Snowflake's principal identity construct is a User - these can represent regular Users, those created using Single Sign-On (SSO) and SCIM, and can also represent 'service accounts' meant for machine-to-machine connectivity.

ElectricEye supports both Password-based and X509-based authentication - either using a password for a 'service account' or a RSA private key and passphrase - the former is much easier, the latter does require saving the certificate to a local file (it will be generated). You can decided to use whichever option you want in the TOML configuration file.

The steps are largely the same for both.

1. In your Snowflake Account, navigate to ... create user

2. Assign a Password, Admin accounts should use Emails so consider that if you'll simply give this use ACCOUNTADMIN...

3. To create an RSA Private Key for you

## Configuring TOML

This section explains how to configure ElectricEye using a TOML configuration file. The configuration file contains settings for credentials, regions, accounts, and global settings and is located [here](../../eeauditor/external_providers.toml).

To configure the TOML file, you need to modify the values of the variables in the `[global]`, `[regions_and_accounts.oci]`, and `[credentials.oci]` sections of the file. Here's an overview of the key variables you need to configure:

- `credentials_location`: Set this variable to specify the location of where credentials are stored and will be retrieved from. You can choose from AWS Systems Manager Parameter Store (`AWS_SSM`), AWS Secrets Manager (`AWS_SECRETS_MANAGER`), or from the TOML file itself (`CONFIG_FILE`) which is **NOT** recommended.

**NOTE** When retrieving from SSM or Secrets Manager, your current Profile / Boto3 Session is used and *NOT* the ElectricEye Role that is specified in `aws_electric_eye_iam_role_name`. Ensure you have `ssm:GetParameter`, `secretsmanager:GetSecretValue`, and relevant `kms` permissions as needed to retrieve your stored secrets.

- `snowflake_username`: Username for your Snowflake Account, this should be a user with the ability to read all tables and views in the default schemas.

- `snowflake_password_value`: The location (or actual contents) of the Password for the User specified in `snowflake_account_id` this location must match the value of `global.credentials_location` e.g., if you specify "AWS_SSM" then the value for this variable should be the name of the AWS Systems Manager Parameter Store SecureString Parameter.

- `snowflake_account_id`: The Account ID for your Snowflake Account, this is found in the URL when you login to your Snowflake Account, e.g., VULEDAR-MR69420.

- `snowflake_warehouse_name`: The name of the warehouse you use for querying data in Snowflake, this should be a warehouse that has the ability to run queries

- `snowflake_region`: The Region of your Snowflake Account, this is found in the URL when you login to your Snowflake Account, e.g., us-east-1

> It's important to note that this setting is a sensitive credential, and as such, its value should be stored in a secure manner that matches the location specified in the `[global]` section's `credentials_location` setting. For example, if `credentials_location` is set to `"AWS_SSM"`, then the Snowflake_service_account_json_payload_value should be the name of an AWS Systems Manager Parameter Store SecureString parameter that contains the contents of the Snowflake service account key JSON file.

## Use ElectricEye for Snowflake

1. With >=Python 3.9 installed, install and upgrade `pip3` and setup `virtualenv`.

```bash
sudo apt install -y python3-pip
pip3 install --upgrade pip
pip3 install virtualenv --user
virtualenv .venv
```

2. This will create a virtualenv directory called `.venv` which needs to be activated.

```bash
#For macOS and Linux
. .venv/bin/activate

#For Windows
.venv\scripts\activate
```

3. Clone the repo and install all dependencies.

```bash
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye
pip3 install -r requirements.txt

# if using AWS CloudShell
pip3 install --user -r requirements.txt
```

4. Use the Controller to conduct different kinds of Assessments.

    - 3A. Retrieve all options for the Controller.

    ```bash
    python3 eeauditor/controller.py --help
    ```

    - 3B. Evaluate your entire Snowflake Account.

    ```bash
    python3 eeauditor/controller.py -t Snowflake
    ```

    - 3C. Evaluate your Snowflake environment against a specifc Auditor (runs all Checks within the Auditor).

    ```bash
    python3 eeauditor/controller.py -t Snowflake -a Snowflake_Account_Auditor
    ```

    - 3D. Evaluate your Snowflake environment against a specific Check within any Auditor, it is ***not required*** to specify the Auditor name as well. The below examples runs the "[Snowflake.Account.9] Snowflake Accounts should configure a password policy" check.

    ```bash
    python3 eeauditor/controller.py -t Snowflake -c snowflake_account_password_policy_check
    ```

## Snowflake Checks & Services

These are the following services and checks performed by each Auditor, there are currently **21 Checks** across **2 Auditors** that support the secure configuration of **3 services/components**

| Auditor File Name | Scanned Resource Name | Auditor Scan Description |
|---|---|---|
| Snowflake_Users_Auditor | Snowflake user | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Users_Auditor | Snowflake user | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Users_Auditor | Snowflake user | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Users_Auditor | Snowflake user | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Users_Auditor | Snowflake user | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Users_Auditor | Snowflake user | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Users_Auditor | Snowflake user | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Users_Auditor | Snowflake user | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Users_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake password policy | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |
| Snowflake_Account_Auditor | Snowflake account | XXXXXXXXXXXXXXXXXXX |