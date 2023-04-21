# ElectricEye Cloud Security Posture Management for Google Cloud Platform (GCP)

This documentation is dedicated to using ElectricEye for evaluation of GCP Environments using CSPM and External Attack Surface Management (EASM) capabilities.

## Table of Contents

- [Quickstart on GCP](#quickstart-on-gcp)
- [GCP EASM Reporting](#gcp-external-attack-surface-reporting)

## Quickstart on GCP

**Note** In the future these GCP-specific docs, as well as the core ElectricEye Controller logic, will be changed to reflect using evaluating an entire GCP Organization

1. Enable the following APIs for all GCP Projects you wish to assess with ElectricEye.

> - Compute Engine API
> - Cloud SQL Admin API
> - Cloud Logging API
> - OS Config API
> - Service Networking API

2. Create a **Service Account** with the following permissions per Project you want to assess with ElectricEye (**Note**: In the future, Organizations will be supported for GCP, you can instead create a single **Service Account** and add it's Email into all of your other Projects)

> - Security Reviewer
> - Project Viewer

3. Create a **JSON Private Key** and upload the full JSON contents to AWS Systems Manager Parameter store as a SecureString. When added into your Parameter Store, you can delete the Private Key JSON file so you do not give it to someone...unsavory.


```bash
export GCP_SA_CRED_SSM_NAME='cool_name_here'
aws ssm put-parameter \
    --name $GCP_SA_CRED_SSM_NAME \
    --description 'GCP SA JSON for [your SA name here?]' \
    --type SecureString \
    --value $PLACEHOLDER
```


4. Modify the [`external_providers.toml`](../eeauditor/external_providers.toml) file to specify the name of the SSM Parameter created in Step 3. ElectricEye will retrieve the JSON contents and write it to a file on your local filesystem and uses the `GOOGLE_APPLICATION_CREDENTIALS` environment variable for the GCP API & CLI (`gcloud`) to specify the credential path. **ElectricEye does not delete this file after it is created, yet**.

```toml
[gcp]
gcp_service_account_json_payload_parameter_name = "<<cool_name_here>>"
```

**Pro Tip**: Rotate your JSON Private Key as often as your internal SOPs dictate, you can even change the entire Parameter as long as you remember to update the `.toml`

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

- 8B. Evaluate your entire GCP environment, for a specific Project.

```bash
export GCP_PROJECT_ID='<My_project_id>'
python3 eeauditor/controller.py -t GCP --gcp-project-id $GCP_PROJECT_ID
```

- 8C. Evaluate your GCP environment against a specifc Auditor (runs all Checks within the Auditor).

```bash
export GCP_PROJECT_ID='<My_project_id>'
python3 eeauditor/controller.py -t GCP -a GCP_ComputeEngine_Auditor --gcp-project-id $GCP_PROJECT_ID
```

- 8D. Evaluate your GCP environment against a specific Check within any Auditor, it is ***not required*** to specify the Auditor name as well. The below examples runs the "[GCP.CloudSQL.1] CloudSQL Instances should not be publicly reachable" check.

```bash
export GCP_PROJECT_ID='<My_project_id>'
python3 eeauditor/controller.py -t GCP -c cloudsql_instance_public_check --gcp-project-id $GCP_PROJECT_ID
```

## GCP External Attack Surface Reporting

If you only wanted to run Attack Surface Monitoring checks use the following command which show an example of outputting the ASM checks into a JSON file for consumption into SIEM or BI tools.

```bash
python3 eeauditor/controller.py -t GCP -a ElectricEye_AttackSurface_GCP_Auditor -o json_normalized --output-file ElectricASM
```