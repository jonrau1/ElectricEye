# ElectricEye Cloud Security Posture Management for Oracle Cloud Infrastructure (OCI)

This documentation is dedicated to using ElectricEye for evaluation of Oracle Cloud Environments using CSPM and External Attack Surface Management (EASM) capabilities.

## Table of Contents

- [Setting up OCI Permissions](#setting-up-oci-permissions)
- [Configuring TOML](#configuring-toml)
- [Use ElectricEye for OCI](#use-electriceye-for-oci)
- [Configuring Security List & NSG Auditors](#configuring-security-list--nsg-auditors)
- [OCI External Attack Surface Reporting](#oci-external-attack-surface-reporting)

## Setting up OCI Permissions

Oracle Cloud Infrastructure Identity and Access Management (IAM) lets you control who has access to your cloud resources. You can control what type of access a group of users have and to which specific resources.

At a high-level, an Oracle Tenancy is a "cloud account" which is a logical container for all of your resources you run in OCI and is controlled by IAM. When you setup your Tenancy you pick a "Home Region" which is a distinct geographical location where the physical infrastrucute and services that underpin Oracle Cloud exist, for instance the `us-ashburn-1` Region is located in Ashburn, Virginia, United States. Depending on your tiering for your Tenancy, you can activate other Regions to build out additional resources, IAM is a global resource and is propagated to the other Regions.

Oracle Cloud can add extra logical separation within a Tenancy by the use of Compartments which is a collection of related resources. Compartments are a fundamental component of Oracle Cloud Infrastructure for organizing and isolating your cloud resources. You use them to clearly separate resources for the purposes of measuring usage and billing, access (through the use of policies), and isolation (separating the resources for one project or business unit from another). A common approach is to create a compartment for each major part of your organization. For more information, see [Learn Best Practices for Setting Up Your Tenancy](https://docs.oracle.com/en-us/iaas/Content/GSG/Concepts/settinguptenancy.htm#Setting_Up_Your_Tenancy).

By default, each Tenancy has a "root" Compartment, which can have up to 5 nested Compartments within them. This is similar to setting up Organizational Units within AWS Organizations or using Folders within a Google Cloud Platform Organization. ElectricEye will natively handle looping through your various Regions and Compartments as long as the User that you setup has the proper Permissions (which this section is dedicated to!)

1. In your OCI Tenancy, navigate to **Identity** -> **Domains**, ensure that you have your "root" Compartment specified in the **List scope** section as shown in the screenshot below.

![OCI Step 1](../../screenshots/setup/oci/setup_1.jpg)

2. Select your **Domain**, it will likely just be `Default`. Navigate to **Groups** and select **Create group** as shown below.

![OCI Step 2](../../screenshots/setup/oci/setup_2.jpg)

3. Enter a **Name** and **Description** for your Group, and select **Create**. We will add a User to this Group later.

4. **OPTIONAL STEP** Navigate to **Identity** -> **Network Sources**, again ensure that you have your "root" Compartment specified in the **List scope** section, and select **Create Network Source**.

5. **OPTIONAL STEP** Enter a **Name** and **Description** for your Network Source. Within **Networks** select *Public Network* and add the CIDR notation to however many IP Addresses you wish to grant access to as shown in the screenshot below. This will be used for a Condition within our OCI Policy, if you will be running ElectricEye from an AWS Account you can add the Elastic IP of a NAT Gateway, you can add the public IP of a GCE/EC2 instance, a Fargate Service, or your own corporate network. You can add more than just a `/32` here to grant access to wider ranges as well. Select **Create** when done.

![OCI Optional Step 5](../../screenshots/setup/oci/optional_setup_5.jpg)

6. Navigate to **Identity** -> **Policies**, again ensure that you have your "root" Compartment specified in the **List scope** section, and select **Create Policy**.

7. Enter a **Name** and **Description** for your Policy. Ensure that the **Compartment** is still your "root" Compartment. Select the toggle for **Show manual editor** as shown in the screenshot below.

![OCI Step 7](../../screenshots/setup/oci/setup_7.jpg)

8. Within the **Policy Builder** paste in one of the following policy snippets depending on the level of access you wish to grant to ElectricEye. Granting access to your entire Tenancy provides access to all Compartments and Regions, you can scope down further to specific Compartments and use Conditional statements to scope down to specific Regions and/or specific Network Sources (if you did `Optional Steps 4 and 5`). Select **Create** when done.

#### IMPORTANT NOTE: Replace <your_group_name> with, you know, your actual Group name you created in Step 3. Leave the single-quotes.

> - Granting Read Access to all resources and log events in your entire Tenancy

```
Allow group 'Default'/'<your_group_name>' to read all-resources in tenancy
Allow group 'Default'/'<your_group_name>' to read audit-events in tenancy
```

> - Granting Read Access to all resources and log events in a specific Compartment. Obviously, replace the value of `my-silly-compartment-name` with your Compartment. You can add multiple lines for multiple compartments.

```
Allow group 'Default'/'<your_group_name>' to read all-resources in compartment my-silly-compartment-name
Allow group 'Default'/'<your_group_name>' to read audit-events in compartment my-silly-compartment-name
```

> - Granting Read Access to all resources and log events in your entire Tenancy for a specific Region, example shown is for Oracle's US West Phoenix, Arizona, United States (`phx`). See [here](https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/commonpolicies.htm#restrict-admin-to-specific-region) for more details.

```
Allow group 'Default'/'<your_group_name>' to read all-resources in tenancy where request.region='phx'
Allow group 'Default'/'<your_group_name>' to read audit-events in tenancy where request.region='phx'
```

> - Granting Read Access to all resources and log events in your entire Tenancy for a specific Network Source (IP-based Restriction), replace the `electriceye-networks` name with the actual name of the Network Source you created in (*Optional!*) Step 5.

```
Allow group 'Default'/'<your_group_name>' to read all-resources in tenancy where request.networkSource.name='electriceye-networks'
Allow group 'Default'/'<your_group_name>' to read audit-events in tenancy where request.networkSource.name='electriceye-networks'
```

#### Another Note: In the future, specifically-scope permissions for the exact APIs needed will be added to `/policies/` in the root directory...

9. In your OCI Tenancy, navigate to **Identity** -> **Domains** -> **`Your Domain`** -> **Users** and select **Create user**.

10. Every OCI user requires an email, you can use a blackhole domain here or your own Email that is different than the email you used for the Tenant Administrator. Add the User in the **Group** you created in Step 3 as shown in the screenshot below and select **Create**.

![OCI Step 10](../../screenshots/setup/oci/setup_10.jpg)

11. Navigate to your **User** and select it, in the `Resources` navigation menu select **API Keys** and then **Add API key**.

12. Choose the option to **Generate API key pair** and then select **Download private key**. This will be `.pem` formatted X.509 certificate that contains all of your permissions. Oracle recommends [changing the file permissions](https://docs.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#two) so only you can view it, if you will be storing the key locally.

13. After creation you will need the **Fingerprint** as well as the contents of the `.pem` file to save to two different AWS SSM Parameter Store SecureString Parameters or AWS Secrets Manager Secrets. If you will be using an SDK or CLI, ensure that you create an enviornment variable or have a way to account for the newlines. For example you can use the following commands, this assumes that you renamed your private key to `oci.pem` and it is in your current directory.

```bash
export OCI_API_KEY_PARAMETER_NAME="oci-api-key"
export OCI_PEM_FINGERPINT='<you_fingerprint_here>'
export OCI_PEM_CONTENTS=$(cat ./oci.pem)

aws ssm put-parameter \
    --name $OCI_PEM_CONTENTS \
    --description 'Oracle Cloud API Key private key for ElectricEye' \
    --type SecureString \
    --value $OCI_API_KEY_PARAMETER_NAME

aws ssm put-parameter \
    --name $OCI_PEM_CONTENTS-fingerprint \
    --description 'Oracle Cloud API Key Fingerprint for ElectricEye' \
    --type SecureString \
    --value $OCI_PEM_FINGERPINT
```

#### NOTE: You can also create an AWS Secrets Manager Secret to store these values

Once you have your API Key private key contents and Fingerprint saved as Parameters or Secrets, proceed to the next section to configure your TOML configuration.

## Configuring TOML

This section explains how to configure ElectricEye using a TOML configuration file. The configuration file contains settings for credentials, regions, accounts, and global settings and is located [here](../../eeauditor/external_providers.toml).



## Use ElectricEye for OCI

## Configuring Security List & NSG Auditors

## OCI External Attack Surface Reporting

If you only wanted to run Attack Surface Monitoring checks use the following command which show an example of outputting the ASM checks into a JSON file for consumption into SIEM or BI tools.

```bash
python3 eeauditor/controller.py -t AWS -a ElectricEye_AttackSurface_OCI_Auditor -o json_normalized --output-file ElectricASMforOCI
```