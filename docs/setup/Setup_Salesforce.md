# ElectricEye SaaS Security Posture Management (SSPM) for Salesforce

This documentation is dedicated to using ElectricEye for evaluation of Salesforce tenants using SSPM capabilities.

## Table of Contents

- [Setting up Salesforce Connected App](#setting-up-salesforce-connected-app)
- [Configuring TOML](#configuring-toml)
- [Use ElectricEye for Salesforce](#use-electriceye-for-salesforce)
- [Salesforce Checks & Services](#salesforce-checks--services)

## Setting up Salesforce Connected App

For a client application (ElectricEye, in this case) to access Salesforce REST API resources, it must be authorized as a safe visitor. To implement this authorization, use a connected app and an OAuth 2.0 authorization flow.

A connected app requests access to REST API resources on behalf of the client application. For a connected app to request access, it must be integrated with your org’s REST API using the OAuth 2.0 protocol. OAuth 2.0 is an open protocol that authorizes secure data sharing between applications through the exchange of tokens.

Connected Apps can be created in: Group, Professional, Enterprise, Essentials, Performance, Unlimited, and Developer Editions. The following user permissions are required, these are subject to change, always refer to the [official Salesforce documentation](https://help.salesforce.com/s/articleView?id=sf.connected_app_create_basics.htm&type=5) to double-check.

| USER ACTIONS | USER PERMISSIONS NEEDED |
|---|---|
| To read, create, update, or delete connected apps | Customize Application AND either </br> Modify All Data OR Manage Connected Apps |
| To update all fields except Profiles, Permission Sets, and Service Provider SAML Attributes | Customize Application AND either </br> Modify All Data OR Manage Connected Apps |
| To update Profiles, Permission Sets, and Service Provider SAML Attributes | Customize Application AND Modify All Data AND Manage Profiles and Permission Sets |
| To rotate the consumer key and consumer secret | Allow consumer key and secret rotation |
| To install and uninstall connected apps | Customize Application AND either </br> Modify All Data OR Manage Connected Apps |
| To install and uninstall packaged connected apps | Customize Application AND either </br> Modify All Data OR Manage Connected Apps </br> AND Download AppExchange Packages |

Use the following steps to create a basic Connected Application.

1. In the navigation menu, navigate to **Apps** -> **App Manager** and select **New Connected App** as shown below.

![Step1](../../screenshots/setup/salesforce/step1.JPG)

2. Enter information for the following fields: **Connected App Name**, **API Name**, **Contact Email** (that is for Salesforce to contact *you*) and optionally: **Logo Image URL** (such as [this one](../../screenshots/smalllogo.png)), **Info URL**, and **Description** as shown below.

![Step2](../../screenshots/setup/salesforce/step2.JPG)

3. Select the option for **Enable OAuth Settings** and enter a **Callback URL** such as `http://localhost:3000/#/signup` or another callback you control. In the **Selected OAuth Scopes** section, add the following permissions as shown in the screenshot below.
- Access Headless Registration API (`user_registration_api`)
- Access Interaction API resources (`interaction_api`)
- Access all Data Cloud API resources (`cdp_api`)
- Access custom permissions (`custom_permissions`)
- Access the Salesforce API Platform (`sfap_api`)
- Access the identity URL service (`id`, `profile`, `email`, `address`, `phone`)
- Access unique user identifiers (`openid`)
- Manage user data via APIs (`api`)
- Perform requests at any time (`refresh_token`, `offline_access`)

![Step3](../../screenshots/setup/salesforce/step3.JPG)

4. Continuing in the `API (Enable OAuth Settings)` section, ensure you select the options for all of: **Require Secret for Web Server Flow**, **Require Secret for Refresh Token Flow** and **Enable Client Credentials Flow**. Select **Configure ID Token** and customize the **Token valid for** value to a value between 2 and 720 minutes as shown below. When you have completed these steps, select **Save** either at the top or bottom of the current page.

![Step4](../../screenshots/setup/salesforce/step4.JPG)

5. Once complete, select **Manage Consumer Details** and copy the values for **Consumer Key** and **Consumer Secret**. These are incredibly sensitive, and should be safeguarded in AWS Secrets Manager, AWS Systems Manager SecureString Parameters or another PIM or vault solution.

6. For the OAuth flow, you will also need to note a **Username** (this is typically your email), your **Password** and you must (re)generate a **Security Token**. You can do this by navigating to **View Profile** -> **Settings** -> **My Personal Information** -> **Reset My Security Token** and selecting **Reset Security Token** which will be emailed to you, as shown below.

![Step6](../../screenshots/setup/salesforce/step6.JPG)

**NOTE** If you will be running ElectricEye from behind a set IP such as a NAT Gateway, an Amazon EC2 Elastic IP, or any other fixed IP ranges consider adding IP allowlists to your Connected App. Double-check that all of your sensitive data is stored in a secure location with strong crytopgrahy that is only accessible to the identity that will run ElectricEye.

7. To access MFA information for users in the `TwoFactorInfo` and `TwoFactorMethodsInfo` APIs, you must add **Manage Multi-Factor Authentication in API** and **Manage Multi-Factor Authentication in User Interface** in the **General User Permissions** section of the assigned Profile as shown below.

![Step7](../../screenshots/setup/salesforce/step7.JPG)

**NOTE** The easiest way to accomplish Step 7 is cloning a `Systems Administrator` or similar default-assigned profile for `Salesforce` licensees and enabling those permissions for your user. You will need another Administrator to change the profile of current Administrators, so you may be required to create or modify another User and swap between sessions to ensure you have the proper permissions.

Once complete, proceed to the next section to learn how to configure the TOML configuration file for ElectricEye.

## Configuring TOML

This section explains how to configure ElectricEye using a TOML configuration file. The configuration file contains settings for credentials, regions, accounts, and global settings and is located [here](../../eeauditor/external_providers.toml).

To configure the TOML file, you need to modify the values of the variables in the `[global]` and `[credentials.salesforce]` sections of the file. Here's an overview of the key variables you need to configure:

- `credentials_location`: Set this variable to specify the location of where credentials are stored and will be retrieved from. You can choose from AWS Systems Manager Parameter Store (`AWS_SSM`), AWS Secrets Manager (`AWS_SECRETS_MANAGER`), or from the TOML file itself (`CONFIG_FILE`) which is **NOT** recommended.

**NOTE** When retrieving from SSM or Secrets Manager, your current Profile / Boto3 Session is used and *NOT* the ElectricEye Role that is specified in `aws_electric_eye_iam_role_name`. Ensure you have `ssm:GetParameter`, `secretsmanager:GetSecretValue`, and relevant `kms` permissions as needed to retrieve this values.

## Use ElectricEye for Salesforce

## Salesforce Checks & Services