# ElectricEye-Response Extras
This section is to walkthrough extra steps for some more advanced playbooks.

## Create_JIRA_Issue_Playbook
This playbook uses the JIRA-python library to parse through information in the Security Hub finding and create a `Bug` issue in your JIRA project of your choosing. You may consider using the [JIRA on AWS Quick Start](https://aws.amazon.com/quickstart/architecture/jira/) if you want to try a POC, Atlassian offers 30-day free evaluation licenses.

### Architecture
This architecture assumes you are running the JIRA Quick Start on AWS, in which case the URL is likely your Load Balancer's DNS name (or whatever domain name you chose). The flow will be no different, just assure you allow access to the Security Group to HTTP(S) or place the Lambda function in a VPC and place them in the same security group.
![JiraPlaybookArchitecture](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/jira-playbook-architecture.jpg)
1. Security Hub Custom Action for the Create JIRA Issue playbook is selected
2. A CloudWatch Event / EventBridge Rule triggers a corresponding Lambda function
3. Lambda retrieves and decrypts the JIRA API key from Systems Manager Parameter Store
4. Information from the Security Hub finding(s) are parsed and a `Bug` is created by your specified User name in the specified Project

### How-to
This section walks through generating or getting the information needed for the Create JIRA Issue Playbook parameters for the ElectricEye-Response semi-auto CFN template.

- **JiraUrl**:
    1. Log into JIRA as your Admin user and select the **Administration** dropdown menu (shaped as a Gear) in the top-right and choose **System**
    2. Copy the value for **Base URL**, this is your JIRA URL

- **JiraProjectKey**:
    1. Select the Projects dropdown on the top-left, the value within parentheses is your Project Key as shown below
    ![JiraProjectKey](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/jira-project-key.JPG)

- **JiraApiKeySSMParameter**:
    1. Navigate to the [Atlassian account management](https://id.atlassian.com/manage/api-tokens) page, log in and select **Create API Token**
    2. Enter a **Label**, select **Create** and select **Copy to clipboard** - you should paste this somewhere safe on your local machine as we will use it for the parameter and the password of our Issue Creator PQML03vep1yzommy7holD21F
    3. Create a SSM Secure String Parameter: `aws ssm put-parameter --name electriceye-response-jira-api-key --description 'API Key for the Create JIRA Issue Playbook' --type SecureString --value <API-KEY-HERE>`

- **JiraIssueCreatorUsername**:
    1. To create a new user select the **Administration** dropdown menu (shaped as a Gear) in the top-right and choose **User management**
    2. Select **Create user** and enter out the required information, paste the value of the API key as your password
    3. Select the **User actions** (represented by an ellipsis on the far right) menu, choose **Edit user groups** and place this user in a Group that allows the creation of Issues (Adminstrators, or otherwise)

## SSM_SNOW_Incident_Playbook
This playbook uses the Systems Manager Automation Document `AWS-CreateServiceNowIncident` to create an Incident in ServiceNow using a user of your choosing. If you do not have a ServiceNow instance and are interested in creating one you can find out more about [Personal Developer Instances (PDIs) here](https://developer.servicenow.com/app.do#!/training/article/app_store_learnv2_buildmyfirstapp_orlando_servicenow_basics/app_store_learnv2_buildmyfirstapp_orlando_personal_developer_instances?v=orlando).

### Architecture
![SnowPlaybookArchitecture](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/snow-playbook-architecture.jpg)
1. Security Hub Custom Action for the Create JIRA Issue playbook is selected
2. A CloudWatch Event / EventBridge Rule triggers a corresponding Lambda function
3. Systems Manager Automation is invoked which executes the `AWS-CreateServiceNowIncident` Document which is provided information from Lambda environmental variables
4. The `AWS-CreateServiceNowIncident` Document retrieves and decrypts from Systems Manager Parameter Store
5. Information from the Security Hub finding(s) are parsed and an Incident is created by your specified User in your Instance

### How-to
This section walks through generating or getting the information needed for the Create SNOW Incident Playbook parameters for the ElectricEye-Response semi-auto CFN template.

- **ServicenowUrl**:
    1. This is the root URL of your instance, if you have a PDI it will be in this format where `12345` should be replaced by the numbers for your instance: `https://dev12345.service-now.com/`

- **ServiceNowIncidentCreator**:
    1. As an Admin user navigate to **User Administration>Users** and select **New** on the top-left
    2. Enter a **User ID** and **Password** and ensure the checkbox for **Active** is checked as shown below and select **Submit**. You will need the password to create the parameter for the next section.
    ![SnowResponseUserCreation](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/snow-response-user-creation.JPG)
    3. Select the User you just created, choose the **Roles** tab on the bottom and select **Edit...**
    4. Add the Role `incident_manager` to your Roles List and select **Save** as shown below
    ![SnowResponseUserRoles](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/snow-response-user-add-role.JPG)

- **IncidentCreatorPasswordSSMParameter**
    1. Create a SSM Secure String Parameter: `aws ssm put-parameter --name electriceye-response-servicenow --description 'Password for the ServiceNow Incident Manager user' --type SecureString --value <PASSWORD-HERE>`