# ElectricEye SaaS Security Posture Management (SSPM) for ServiceNow

This documentation is dedicated to using ElectricEye for evaluation of ServiceNow Environments

## Table of Contents

- [Quickstart on ServiceNow](#quickstart-on-servicenow)

## Quickstart on ServiceNow

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

4. Modify the [`external_providers.toml`](../eeauditor/external_providers.toml) file to add your **Username**, **Password Parameter**, and your **Servicenow Instance Name**. Regarding the instance name, if the URL of your instance is "https://dev90210.service-now.com/" then your instance name is "dev90210". Be sure to replace the example values listed below. Lastly, specify a "breaching rate" to alert on consecutive failed login attempts per-user (Active users only), it defaults to **5**.

```toml
[servicenow]
snow_instance_name = "dev90210"
snow_sspm_username = "electriceye_sspm"
snow_sspm_password_parameter_name = $SNOW_PW_PARAMETER_NAME
snow_failed_login_breaching_rate = 5
```

5. With >=Python 3.6 installed, install and upgrade `pip3` and setup `virtualenv`.

```bash
sudo apt install -y python3-pip
pip3 install --upgrade pip
pip3 install virtualenv --user
virtualenv .venv
```

6. This will create a virtualenv directory called `.venv` which needs to be activated.

```bash
#For macOS and Linux
. .venv/bin/activate

#For Windows
.venv\scripts\activate
```

7. Clone the repo and install all dependencies.

```bash
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye
pip3 install -r requirements.txt

# if use AWS CloudShell
pip3 install --user -r requirements.txt
```

8. Use the Controller to conduct different kinds of Assessments.

- 8A. Retrieve all options for the Controller.

```bash
python3 eeauditor/controller.py --help
```

- 8B. Evaluate your entire ServiceNow instance.

```bash
python3 eeauditor/controller.py -t Servicenow
```

- 8C. Evaluate your ServiceNow instance against a specifc Auditor (runs all Checks within the Auditor).

```bash
python3 eeauditor/controller.py -t Servicenow -a Servicenow_Users_Auditor
```

- 8D. Evaluate your ServiceNow instance against a specific Check within any Auditor, it is ***not required*** to specify the Auditor name as well. The below examples runs the "[SSPM.Servicenow.AccessControl.1] Instance should block access to GlideSystemUserSession scriptable API unsanitized messages" check.

```bash
python3 eeauditor/controller.py -t Servicenow -c servicenow_sspm_user_session_allow_unsanitzed_messages_check
```