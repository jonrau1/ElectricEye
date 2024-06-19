# ElectricEye SaaS Security Posture Management (SSPM) for ServiceNow

This documentation is dedicated to using ElectricEye for evaluation of ServiceNow instances using SSPM capabilities.

## Table of Contents

- [Configuring TOML](#configuring-toml)
- [Quickstart on ServiceNow](#use-electriceye-for-servicenow)
- [Servicenow Checks & Services](#servicenow-checks--services)

## Configuring TOML

This section explains how to configure ElectricEye using a TOML configuration file. The configuration file contains settings for credentials, regions, accounts, and global settings and is located [here](../../eeauditor/external_providers.toml).

To configure the TOML file, you need to modify the values of the variables in the `[global]` and `[credentials.servicenow]` sections of the file. Here's an overview of the key variables you need to configure:

- `credentials_location`: Set this variable to specify the location of where credentials are stored and will be retrieved from. You can choose from AWS Systems Manager Parameter Store (`AWS_SSM`), AWS Secrets Manager (`AWS_SECRETS_MANAGER`), or from the TOML file itself (`CONFIG_FILE`) which is **NOT** recommended.

**NOTE** When retrieving from SSM or Secrets Manager, your current Profile / Boto3 Session is used and *NOT* the ElectricEye Role that is specified in `aws_electric_eye_iam_role_name`. Ensure you have `ssm:GetParameter`, `secretsmanager:GetSecretValue`, and relevant `kms` permissions as needed to retrieve this values.

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


4. With >=Python 3.9 installed, install and upgrade `pip3` and setup `virtualenv`.

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

## Servicenow Checks & Services

These are the following services and checks perform by each Auditor, there are currently **92 Checks** across **9 Auditors** that support the secure configuration of **3 services/components**

| Auditor File Name | Scanned Resource Name | Auditor Scan Description |
|---|---|---|
| Servicenow_Users_Auditor | Servicenow User | Do active users have MFA enabled |
| Servicenow_Users_Auditor | Servicenow User | Audit active users for {X} failed login attempts |
| Servicenow_Users_Auditor | Servicenow User | Audit active users that are locked out |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance block unsanitized messages |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance specify a script execution role |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for JSONv2 API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for SOAP API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does instance block delegated developer grant roles |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for CSV API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce default deny |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance double-check inbound form transactions |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance control live profile details |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for GlideAjax API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for Excel API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for the import API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for PDF API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance protect performance monitoring for unauthorized access |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance restrict performance monitoring to specific IP |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enable privacy control for client-callable scripts |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance restrict Favorites access |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance have an IP Allowlist |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for RSS API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for Script Requests API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance perform validation for SOAP requests |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance restrict ServiceNow employee access
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for Unload API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for WSDL API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for XML API |
| Servicenow_AccessControl_Auditor | System Property | Access Control: Does the instance enforce basic AuthN for XSD API |
| Servicenow_Attachments_Auditor | System Property | Attachments: Does the instance restrict files from being rendered in the browser |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should restrict questionable file attachments |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should configure file download restrictions |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should enable access control for profile pictures |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should enforce downloading of attachments |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should define file type allowlist for uploads |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should prevent unauthorized access to attachments |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should prevent specific file extensions upload |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should prevent specific file type upload |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should prevent specific file type download |
| Servicenow_Attachments_Auditor | System Property | Attachments: Instance should enable MIME type validation |
| Servicenow_EmailSecurity_Auditor | System Property | Email Security: Instance should restrict email HTML bodies from rendering |
| Servicenow_EmailSecurity_Auditor | System Property | Email Security: Instance should restrict acccess to emails with empty target tables |
| Servicenow_EmailSecurity_Auditor | System Property | Email Security: Instance should specify trusted domain allowlists |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should disallow embedded HTML code |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should disallow JavaScript in embedded HTML |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should check unsanitized HTML |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should enable script sandboxing |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should disable AJAXEvaluate |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should escape Excel formula injection |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should escape HTML |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should escape JavaScript |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should escape Jelly |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should escape XML |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should sanitize HTML |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should prevent JavaScript injection with Jelly interpolation |
| Servicenow_InputValidation_Auditor | System Property | Input Validation: Instance should enable SOAP request strict security |
| Servicenow_SecureCommunications_Auditor | System Property | Secure Communications: Instance should enable certficate validation on outbound connections |
| Servicenow_SecureCommunications_Auditor | System Property | Secure Communications: Instance should disable SSLv2 & SSLv3 |
| Servicenow_SecureCommunications_Auditor | System Property | Secure Communications: Instance should verify HTTP client hostnames |
| Servicenow_SecureCommunications_Auditor | System Property | Secure Communications: Instance should check revoked certificate status |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should enable URL allow list for cross-origin iframe communication |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should enforce relative links |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should specify URL allow list for cross-origin iframe communication |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should specify URL allow list for logout redirects |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set virtual agent embedded client content security policy |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set virtual agent embedded client X-Frame-Options |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set X-Frame-Options: SAMEORIGIN |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set XXE entity expansion threshold |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set XMLdoc/XMLUtil entity validation allow list |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should disable XXE entity expansion |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should set XMLdoc2 entity validation allow list |
| Servicenow_SecurityInclusionListing_Auditor | System Property | Security Inclusion Listing: Instance should enable XML external entity processing allow lists |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should set absolute session timeouts |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should set an Anti-CSRF token |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should set the HTTPOnly property for sensitive cookies |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should enable Anti-CSRF token strict validation |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should disable passwordless authentication |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should globally enable MFA |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should enforce password change validation |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should disable password autocompletes |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should disable Remember Me checkboxes |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should rotate HTTP SessionIDs |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should validate session cookies |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should set a strong security reference policy |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: Instance should set a strong session activity timeout |
| Servicenow_SessionManagement_Auditor | System Property | Session Management: If using Remember Me, instance should set a strong rotation timeout |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the Contextual Security: Role Management Plugin intalled and active |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the Explicit Role Plugin intalled and active |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the SAML 2.0 SSO Plugin intalled and active |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the Security Jump Start Plugin intalled and active |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the SNC Access Control Plugin intalled and active |
| Servicenow_SecurityPlugins_Auditor | Plugin | Plugins: Instance should have the Email Filters Plugin intalled and active |

Continue to check this section for information on active, retired, and renamed checks or using the `--list-checks` command in the CLI!