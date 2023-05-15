# ElectricEye Cloud Security Posture Management for Google Cloud Platform (GCP)

This documentation is dedicated to using ElectricEye for evaluation of GCP Environments using CSPM and External Attack Surface Management (EASM) capabilities.

## Table of Contents

- [Configuring TOML](#)
- [Use ElectricEye for GCP](#use-electriceye-for-gcp)
- [GCP EASM Reporting](#gcp-external-attack-surface-reporting)
- [GCP Multi-Project Service Account Support](#gcp-multi-project-service-account-support)

## Configuring TOML

This section explains how to configure ElectricEye using a TOML configuration file. The configuration file contains settings for credentials, regions, accounts, and global settings and is located [here](../../eeauditor/external_providers.toml).

To configure the TOML file, you need to modify the values of the variables in the `[global]`, `[regions_and_accounts.gcp]`, and `[credentials.gcp]` sections of the file. Here's an overview of the key variables you need to configure:

- `credentials_location`: Set this variable to specify the location of where credentials are stored and will be retrieved from. You can choose from AWS Systems Manager Parameter Store (`AWS_SSM`), AWS Secrets Manager (`AWS_SECRETS_MANAGER`), or from the TOML file itself (`CONFIG_FILE`) which is **NOT** recommended.

- `gcp_project_ids`: Set this variable to specify a list of GCP Project IDs, ensure you only specify the GCP Projects which the Service Account specified in `gcp_service_account_json_payload_value` has access to.

- `gcp_service_account_json_payload_value`: This variable is used to specify the contents of the Google Cloud Platform (GCP) service account key JSON file that ElectricEye should use to authenticate to GCP. The contents of the JSON file should be provided as a string, and the entire string should be assigned to the `gcp_service_account_json_payload_value` setting.

It's important to note that this setting is a sensitive credential, and as such, its value should be stored in a secure manner that matches the location specified in the `[global]` section's `credentials_location` setting. For example, if `credentials_location` is set to `"AWS_SSM"`, then the gcp_service_account_json_payload_value should be the name of an AWS Systems Manager Parameter Store SecureString parameter that contains the contents of the GCP service account key JSON file.

Refer [here](#gcp-multi-project-service-account-support) for information on adding permissions for your Service Account to other Projects.

## Use ElectricEye for GCP

1. Enable the following APIs for all GCP Projects you wish to assess with ElectricEye.

> - Compute Engine API
> - Cloud SQL Admin API
> - Cloud Logging API
> - OS Config API
> - Service Networking API

2. Create a **Service Account** with the following permissions per Project you want to assess with ElectricEye (**Note**: In the future, Organizations will be supported for GCP, you can instead create a single **Service Account** and add it's Email into all of your other Projects)

> - Security Reviewer
> - Project Viewer

#### NOTE: For evaluating multiple GCP Projects, you only need ONE Service Account, refer to [GCP Multi-Project Service Account Support](#gcp-multi-project-service-account-support) for more information on adding permissions to other Projects.

3. Create a **JSON Private Key** and upload the full JSON contents to AWS Systems Manager Parameter store as a SecureString. When added into your Parameter Store, you can delete the Private Key JSON file so you do not give it to someone...unsavory.

```bash
export GCP_SA_CRED_SSM_NAME='cool_name_here'
aws ssm put-parameter \
    --name $GCP_SA_CRED_SSM_NAME \
    --description 'GCP SA JSON for [your SA name here?]' \
    --type SecureString \
    --value $PLACEHOLDER
```

#### NOTE: You can also save this value as an AWS Secrets Manager Secret!

#### NOTE: Rotate your JSON Private Key as often as your internal SOPs dictate, you can even change the entire Parameter as long as you remember to update the `.toml`

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

    - 7B. Evaluate your entire GCP environment, for a specific Project.

    ```bash
    python3 eeauditor/controller.py -t GCP
    ```

    - 7C. Evaluate your GCP environment against a specifc Auditor (runs all Checks within the Auditor).

    ```bash
    python3 eeauditor/controller.py -t GCP -a GCP_ComputeEngine_Auditor
    ```

    - 7D. Evaluate your GCP environment against a specific Check within any Auditor, it is ***not required*** to specify the Auditor name as well. The below examples runs the "[GCP.CloudSQL.1] CloudSQL Instances should not be publicly reachable" check.

    ```bash
    python3 eeauditor/controller.py -t GCP -c cloudsql_instance_public_check
    ```

## GCP External Attack Surface Reporting

If you only wanted to run Attack Surface Monitoring checks use the following command which show an example of outputting the ASM checks into a JSON file for consumption into SIEM or BI tools.

```bash
python3 eeauditor/controller.py -t GCP -a ElectricEye_AttackSurface_GCP_Auditor -o json_normalized --output-file ElectricASM
```

## GCP Multi-Project Service Account Support

ElectricEye utilizes the JSON Key from a GCP Service Account (SA) to provide permissions into the Python Client SDK that is used for GCP Auditors. To support cross-account (cross-Project) evaluations, you must grant access to your main SA (let's say in `project-a`) to your other Projects (let's say `project-moose` and `project-sandstone`) and add GCP IAM Roles there.

**NOTE!** You will either need `Owner` or at the very least `resourcemanager.projects.setIamPolicy` Permissions in each Project you wish to do this for.

1. Navigate to the **IAM & Admin** page for each of the Projects (`project-moose` and `project-`sandstone) that you want to grant access to.

2. Select **Grant Access** to add a new member, underneath **Add principals** enter the `Email` of the SA in `project-a` that should more or less follow this pattern: `<service_account_name>@<project_a_id>.iam.gserviceaccount.com`

3. In the **Assign roles** drop-down menu, search for and select the `Viewer` and `Security Reviewer` roles and select **Save**. Repeat this for all of your Projects.

Alternatively this can be done via `gcloud` within the GCP Console or remotely

```bash
SERVICE_ACCOUNT_EMAIL='<service_account_name>@<project_a_id>.iam.gserviceaccount.com'
PROJECT_LIST==(project-a project-b project-c)
for project_id in "${PROJECT_LIST[@]}"
do
  gcloud projects add-iam-policy-binding $project_id --member=$SERVICE_ACCOUNT_EMAIL --role=roles/iam.securityReviewer
  gcloud projects add-iam-policy-binding $project_id --member=$SERVICE_ACCOUNT_EMAIL --role=roles/viewer
done
```