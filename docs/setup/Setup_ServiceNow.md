# ElectricEye SaaS Security Posture Management (SSPM) for ServiceNow

This documentation is dedicated to using ElectricEye for evaluation of ServiceNow instances using SSPM capabilities.

## Table of Contents

- [Configuring TOML](#configuring-toml)
- [Quickstart on ServiceNow](#use-electriceye-for-servicenow)

## Configuring TOML

This section explains how to configure ElectricEye using a TOML configuration file. The configuration file contains settings for credentials, regions, accounts, and global settings and is located [here](../../eeauditor/external_providers.toml).

To configure the TOML file, you need to modify the values of the variables in the `[global]` and `[credentials.servicenow]` sections of the file. Here's an overview of the key variables you need to configure:

- `credentials_location`: Set this variable to specify the location of where credentials are stored and will be retrieved from. You can choose from AWS Systems Manager Parameter Store (`AWS_SSM`), AWS Secrets Manager (`AWS_SECRETS_MANAGER`), or from the TOML file itself (`CONFIG_FILE`) which is **NOT** recommended.

- `servicenow_instance_name`: The name of your ServiceNow Instance. For example, if your ServiceNow URL is "https://dev90210.service-now.com/", the name is "dev90210".

- `servicenow_instance_region`: The geographic location of your ServiceNow Instance which will be provided to ProductFields.AssetRegion within the ElectricEye findings. This is typically `"us"`, `"eu"`, or `"ap"` and may differ for Federal instances.

- `servicenow_sspm_username`: The name of the ServiceNow User with permissions that will be used by the PySNOW Client.

- `servicenow_sspm_password_value`: The location (or actual contents) of the Password for the User specified in servicenow_instance_name. This location must match the value of global.credentials_location. For example, if you specify `"AWS_SSM"`, then the value for this variable should be the name of the AWS Systems Manager Parameter Store SecureString Parameter.

- `servicenow_failed_login_breaching_rate`: The threshold for when to create a failing finding for the "ServiceNow_Users_Auditor" check for failed login-in attempts by active users in your ServiceNow Instance. The default value is "5".

## Use ElectricEye for ServiceNow

**Note:** Currently, ElectricEye SSPM for Servicenow relies on a User being created with a specific Role, in the future this may change to an OAuth or Integration User. Also, the Instructions to add the `admin` Role are over-permissive and will be scaled down properly for subsequent releases after testing.

1. In Servicenow create a new User with a `User ID` of `**electriceye_sspm**` and add the `admin` Role as an assignment.

2. Select **Set Password** and generate a password, create an AWS Systems Manager `SecureString` Parameter for this value.

```bash
export SNOW_PW_PARAMETER_NAME='cool_name_here'
aws ssm put-parameter \
    --name $SNOW_PW_PARAMETER_NAME \
    --description 'ElectricEye SSPM Servicenow Password for electriceye_sspm' \
    --type SecureString \
    --value $PLACEHOLDER
```

3. Set the value of **Password needs reset** to false and **Update** the User to save changes.


4. With >=Python 3.6 installed, install and upgrade `pip3` and setup `virtualenv`.

```bash
sudo apt install -y python3-pip
pip3 install --upgrade pip
pip3 install virtualenv --user
virtualenv .venv
```

5. This will create a virtualenv directory called `.venv` which needs to be activated.

```bash
#For macOS and Linux
. .venv/bin/activate

#For Windows
.venv\scripts\activate
```

6. Clone the repo and install all dependencies.

```bash
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye
pip3 install -r requirements.txt

# if use AWS CloudShell
pip3 install --user -r requirements.txt
```

7. Use the Controller to conduct different kinds of Assessments.

    - 7A. Retrieve all options for the Controller.

    ```bash
    python3 eeauditor/controller.py --help
    ```

    - 7B. Evaluate your entire ServiceNow instance.

    ```bash
    python3 eeauditor/controller.py -t Servicenow
    ```

    - 7C. Evaluate your ServiceNow instance against a specifc Auditor (runs all Checks within the Auditor).

    ```bash
    python3 eeauditor/controller.py -t Servicenow -a Servicenow_Users_Auditor
    ```

    - 7D. Evaluate your ServiceNow instance against a specific Check within any Auditor, it is ***not required*** to specify the Auditor name as well. The below examples runs the "[SSPM.Servicenow.AccessControl.1] Instance should block access to GlideSystemUserSession scriptable API unsanitized messages" check.

    ```bash
    python3 eeauditor/controller.py -t Servicenow -c servicenow_sspm_user_session_allow_unsanitzed_messages_check
    ```